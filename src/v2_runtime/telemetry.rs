//! Atomic telemetry collection and interval snapshots for the V2 runtime.
//!
//! This is an internal leaf: it owns counter mutation, immutable sampling
//! windows, and status traffic projection. The runtime retains the scheduling
//! and policy decisions that consume those values.

use iroh::TransportAddr;

use std::{
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::Instant,
};

use crate::protocol::v2::{
    cell::TrafficClass,
    dataplane::{RepairRequestBatchV2, RepairResponseObservationV2, SendProgress},
    fec::LossRunHistogramV2,
    feedback::FecFeedbackV2,
    gso::GsoObservationV2,
    reassembly::ReassemblyOutput,
    repair::{RepairControlV2, RepairRequestV2},
    utility::WireCostV2,
};

const LATENCY_SOJOURN_UPPER_MICROS: [u64; 12] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 1_000_000,
];
const LATENCY_SOJOURN_BUCKETS: usize = LATENCY_SOJOURN_UPPER_MICROS.len() + 1;
const BULK_FAIRNESS_BUCKETS: usize = 32;

pub(super) fn path_endpoint_identity(remote: &TransportAddr) -> String {
    // noq can recycle its internal PathId during validation/maintenance even
    // when the underlying network path is unchanged, and its local address
    // can move between unresolved/resolved representations during that same
    // maintenance cycle. The authenticated peer's selected remote locator is
    // the stable path identity: it still distinguishes IPv4, IPv6, DERP
    // region/key and address-family/network changes without manufacturing
    // five-second epochs for harmless QUIC/NAT source-port rebinding.
    match remote {
        TransportAddr::Ip(address) => format!("ip:{}", address.ip()),
        TransportAddr::Custom(address) => format!("custom:{address:?}"),
        _ => format!("other:{remote:?}"),
    }
}

#[derive(Debug, Default)]
pub(super) struct RuntimeMetrics {
    /// Live directional first-hop capacity used by demand-aware route leases.
    /// The tuner publishes the BBR delivery model in bits/s; zero means cold.
    pub(super) route_capacity_bps: AtomicU64,
    pub(super) route_switches: AtomicU64,
    pub(super) train_queue_bytes: AtomicU64,
    pub(super) latency_queue_bytes: AtomicU64,
    pub(super) real_tx_bytes: AtomicU64,
    pub(super) cover_tx_bytes: AtomicU64,
    pub(super) cover_rx_bytes: AtomicU64,
    pub(super) pmtu_drop_bytes: AtomicU64,
    pub(super) pmtu_drop_datagrams: AtomicU64,
    pub(super) tun_tx_packets: AtomicU64,
    pub(super) tun_rx_packets: AtomicU64,
    pub(super) tun_rx_bytes: AtomicU64,
    pub(super) tun_ingress_records: AtomicU64,
    pub(super) tun_ingress_bytes: AtomicU64,
    pub(super) tun_admission_drop_records: AtomicU64,
    pub(super) tun_admission_drop_bytes: AtomicU64,
    pub(super) data_cell_tx_datagrams: AtomicU64,
    pub(super) full_payload_cells_built: AtomicU64,
    pub(super) data_cell_tx_bytes: AtomicU64,
    pub(super) data_cell_payload_tx_bytes: AtomicU64,
    pub(super) fec_tx_datagrams: AtomicU64,
    pub(super) fec_tx_bytes: AtomicU64,
    pub(super) control_record_tx_bytes: AtomicU64,
    pub(super) control_record_rx_bytes: AtomicU64,
    pub(super) repair_request_tx_bytes: AtomicU64,
    pub(super) repair_request_rx_bytes: AtomicU64,
    pub(super) repair_response_tx_bytes: AtomicU64,
    pub(super) repair_response_rx_bytes: AtomicU64,
    pub(super) trains_built: AtomicU64,
    pub(super) records_built: AtomicU64,
    pub(super) record_bytes_built: AtomicU64,
    pub(super) split_records_built: AtomicU64,
    pub(super) cells_built: AtomicU64,
    pub(super) cell_payload_built_bytes: AtomicU64,
    pub(super) cell_wire_built_bytes: AtomicU64,
    pub(super) unused_cell_capacity_bytes: AtomicU64,
    pub(super) fec_stripes_built: AtomicU64,
    pub(super) fec_protected_data_cells: AtomicU64,
    pub(super) fec_parity_cells_built: AtomicU64,
    pub(super) fec_encode_copy_bytes: AtomicU64,
    pub(super) fec_unprotected_tail_cells: AtomicU64,
    pub(super) fec_parity_rx: AtomicU64,
    pub(super) fec_recovered_cells: AtomicU64,
    pub(super) fec_wasted_parity: AtomicU64,
    pub(super) fec_expired_stripes: AtomicU64,
    pub(super) fec_decode_copy_bytes: AtomicU64,
    pub(super) fec_recovery_latency_micros: AtomicU64,
    pub(super) repair_requested_cells: AtomicU64,
    pub(super) repair_suppressed_stripes: AtomicU64,
    pub(super) repair_suppressed_cells: AtomicU64,
    pub(super) repair_received_cells: AtomicU64,
    pub(super) repair_completed_requests: AtomicU64,
    pub(super) repair_completed_requested_cells: AtomicU64,
    pub(super) repair_latency_micros: AtomicU64,
    pub(super) repair_latency_max_micros: AtomicU64,
    pub(super) repair_stale_responses: AtomicU64,
    pub(super) repair_minimum_age_micros: AtomicU64,
    /// `RepairWaitPolicyV2` metrics code published by the tuner loop.
    pub(super) repair_wait_policy: AtomicU8,
    pub(super) remote_feedback_sequence: AtomicU64,
    pub(super) remote_fec_parity_rx: AtomicU64,
    pub(super) remote_fec_recovered_cells: AtomicU64,
    pub(super) remote_fec_wasted_parity: AtomicU64,
    pub(super) remote_fec_expired_stripes: AtomicU64,
    pub(super) remote_repair_requested_cells: AtomicU64,
    pub(super) remote_repair_received_cells: AtomicU64,
    pub(super) remote_repair_completed_requests: AtomicU64,
    pub(super) remote_repair_completed_requested_cells: AtomicU64,
    pub(super) remote_repair_latency_micros: AtomicU64,
    pub(super) remote_delivered_payload_bytes: AtomicU64,
    pub(super) remote_reorder_cells: AtomicU64,
    pub(super) remote_missing_cells: AtomicU64,
    pub(super) remote_loss_run_1: AtomicU64,
    pub(super) remote_loss_run_2: AtomicU64,
    pub(super) remote_loss_run_3_4: AtomicU64,
    pub(super) remote_loss_run_5_plus: AtomicU64,
    pub(super) remote_reassembly_expired_trains: AtomicU64,
    pub(super) receive_buffer_bytes: AtomicU64,
    /// Policy-driven aggregate reassembly budget (0 = follow the receive
    /// buffer), published by the tuner loop.
    pub(super) reassembly_budget_bytes: AtomicU64,
    /// Policy-driven active-train budget (0 = negotiated wire limit).
    pub(super) active_train_budget: AtomicU64,
    pub(super) reassembly_pressure_evictions: AtomicU64,
    pub(super) reassembly_expired_trains: AtomicU64,
    pub(super) reorder_cells: AtomicU64,
    pub(super) missing_cells: AtomicU64,
    pub(super) loss_run_1: AtomicU64,
    pub(super) loss_run_2: AtomicU64,
    pub(super) loss_run_3_4: AtomicU64,
    pub(super) loss_run_5_plus: AtomicU64,
    pub(super) gso_input_bytes: AtomicU64,
    pub(super) gso_preserved_bytes: AtomicU64,
    pub(super) gso_fallback_splits: AtomicU64,
    pub(super) protocol_datagram_errors: AtomicU64,
    pub(super) route_gate_drops: AtomicU64,
    /// Bytes admitted to the Bulk scheduler class. Unlike
    /// `bulk_service_bytes`, this advances before QUIC can transmit the
    /// queued work and therefore remains useful when a stale congestion
    /// model is preventing that first send.
    pub(super) bulk_admission_bytes: AtomicU64,
    pub(super) bulk_service_bytes: AtomicU64,
    pub(super) latency_service_bytes: AtomicU64,
    pub(super) bulk_service_quantums: AtomicU64,
    pub(super) latency_service_quantums: AtomicU64,
    pub(super) bulk_preemptions: AtomicU64,
    pub(super) bulk_preemption_delay_micros: AtomicU64,
    pub(super) bulk_preemption_max_delay_micros: AtomicU64,
    pub(super) latency_sojourn_buckets: [AtomicU64; LATENCY_SOJOURN_BUCKETS],
    pub(super) bulk_flow_service: [AtomicU64; BULK_FAIRNESS_BUCKETS],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct TxByteSnapshotV2 {
    pub(super) quic_udp_payload_bytes: u64,
    pub(super) real_record_bytes: u64,
    pub(super) data_cell_bytes: u64,
    pub(super) data_cell_payload_bytes: u64,
    pub(super) fec_bytes: u64,
    pub(super) control_record_bytes: u64,
    pub(super) repair_request_bytes: u64,
    pub(super) repair_response_bytes: u64,
    pub(super) padding_bytes: u64,
}

impl TxByteSnapshotV2 {
    pub(super) fn load(metrics: &RuntimeMetrics, quic_udp_payload_bytes: u64) -> Self {
        Self {
            quic_udp_payload_bytes,
            real_record_bytes: metrics.record_bytes_built.load(Ordering::Relaxed),
            data_cell_bytes: metrics.data_cell_tx_bytes.load(Ordering::Relaxed),
            data_cell_payload_bytes: metrics.data_cell_payload_tx_bytes.load(Ordering::Relaxed),
            fec_bytes: metrics.fec_tx_bytes.load(Ordering::Relaxed),
            control_record_bytes: metrics.control_record_tx_bytes.load(Ordering::Relaxed),
            repair_request_bytes: metrics.repair_request_tx_bytes.load(Ordering::Relaxed),
            repair_response_bytes: metrics.repair_response_tx_bytes.load(Ordering::Relaxed),
            padding_bytes: metrics.cover_tx_bytes.load(Ordering::Relaxed),
        }
    }

    pub(super) fn delta(self, previous: Self) -> Self {
        Self {
            quic_udp_payload_bytes: counter_delta(
                self.quic_udp_payload_bytes,
                previous.quic_udp_payload_bytes,
            ),
            real_record_bytes: self
                .real_record_bytes
                .saturating_sub(previous.real_record_bytes),
            data_cell_bytes: self
                .data_cell_bytes
                .saturating_sub(previous.data_cell_bytes),
            data_cell_payload_bytes: self
                .data_cell_payload_bytes
                .saturating_sub(previous.data_cell_payload_bytes),
            fec_bytes: self.fec_bytes.saturating_sub(previous.fec_bytes),
            control_record_bytes: self
                .control_record_bytes
                .saturating_sub(previous.control_record_bytes),
            repair_request_bytes: self
                .repair_request_bytes
                .saturating_sub(previous.repair_request_bytes),
            repair_response_bytes: self
                .repair_response_bytes
                .saturating_sub(previous.repair_response_bytes),
            padding_bytes: self.padding_bytes.saturating_sub(previous.padding_bytes),
        }
    }

    pub(super) fn breakdown(self) -> TxByteBreakdownV2 {
        let repair_bytes = self
            .repair_request_bytes
            .saturating_add(self.repair_response_bytes)
            .min(self.control_record_bytes);
        let application_bytes = self
            .data_cell_bytes
            .saturating_add(self.fec_bytes)
            .saturating_add(self.control_record_bytes)
            .saturating_add(self.padding_bytes);
        TxByteBreakdownV2 {
            quic_udp_payload_bytes: self.quic_udp_payload_bytes,
            real_record_bytes: self.real_record_bytes,
            data_cell_bytes: self.data_cell_bytes,
            data_cell_payload_bytes: self.data_cell_payload_bytes,
            packet_train_metadata_bytes: self
                .data_cell_payload_bytes
                .saturating_sub(self.real_record_bytes),
            cell_envelope_bytes: self
                .data_cell_bytes
                .saturating_sub(self.data_cell_payload_bytes),
            fec_bytes: self.fec_bytes,
            repair_request_bytes: self.repair_request_bytes,
            repair_response_bytes: self.repair_response_bytes,
            other_control_record_bytes: self.control_record_bytes.saturating_sub(repair_bytes),
            padding_bytes: self.padding_bytes,
            quic_transport_residual_bytes: self
                .quic_udp_payload_bytes
                .saturating_sub(application_bytes),
            interval_accounting_lag_bytes: application_bytes
                .saturating_sub(self.quic_udp_payload_bytes),
        }
    }
}

/// A status-interval ledger. QUIC's counter includes every byte carried
/// inside UDP datagrams. DATAGRAM payload, reliable control records and cover
/// padding are counted at successful QUIC admission; their positive residual
/// is therefore QUIC packet/frame/AEAD/ACK/retransmission overhead. A positive
/// lag is reported separately instead of pretending that asynchronous QUIC
/// serialization at an interval boundary is protocol overhead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct TxByteBreakdownV2 {
    pub(super) quic_udp_payload_bytes: u64,
    pub(super) real_record_bytes: u64,
    pub(super) data_cell_bytes: u64,
    pub(super) data_cell_payload_bytes: u64,
    pub(super) packet_train_metadata_bytes: u64,
    pub(super) cell_envelope_bytes: u64,
    pub(super) fec_bytes: u64,
    pub(super) repair_request_bytes: u64,
    pub(super) repair_response_bytes: u64,
    pub(super) other_control_record_bytes: u64,
    pub(super) padding_bytes: u64,
    pub(super) quic_transport_residual_bytes: u64,
    pub(super) interval_accounting_lag_bytes: u64,
}

impl TxByteBreakdownV2 {
    pub(super) fn wire_cost(self) -> WireCostV2 {
        WireCostV2 {
            payload_bytes: self.real_record_bytes,
            parity_bytes: self.fec_bytes,
            repair_bytes: self
                .repair_request_bytes
                .saturating_add(self.repair_response_bytes),
            cover_bytes: self.padding_bytes,
            cell_envelope_bytes: self.cell_envelope_bytes,
        }
    }
}

/// Counters consumed by every tuner sample. Capturing them together keeps the
/// rate calculations and their next baseline on the same sampling boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SampleCounterSnapshot {
    pub(super) real_bytes: u64,
    pub(super) tun_ingress_records: u64,
    pub(super) tun_ingress_bytes: u64,
    pub(super) gso_input_bytes: u64,
    pub(super) reassembly_pressure_evictions: u64,
    pub(super) train_build_bytes: u64,
    pub(super) bulk_preemptions: u64,
    pub(super) bulk_preemption_delay_micros: u64,
    pub(super) utility_tx_bytes: TxByteSnapshotV2,
    pub(super) latency_sojourn: [u64; LATENCY_SOJOURN_BUCKETS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SampleCounterDelta {
    pub(super) real_bytes: u64,
    pub(super) tun_ingress_records: u64,
    pub(super) tun_ingress_bytes: u64,
    pub(super) gso_input_bytes: u64,
    pub(super) reassembly_pressure_evictions: u64,
    pub(super) train_build_bytes: u64,
    pub(super) bulk_preemptions: u64,
    pub(super) bulk_preemption_delay_micros: u64,
    pub(super) latency_sojourn: [u64; LATENCY_SOJOURN_BUCKETS],
}

impl SampleCounterSnapshot {
    pub(super) fn capture(metrics: &RuntimeMetrics, udp_tx_bytes: u64) -> Self {
        Self::capture_with_tx(metrics, TxByteSnapshotV2::load(metrics, udp_tx_bytes))
    }

    pub(super) fn capture_with_tx(
        metrics: &RuntimeMetrics,
        utility_tx_bytes: TxByteSnapshotV2,
    ) -> Self {
        Self {
            real_bytes: metrics.real_tx_bytes.load(Ordering::Relaxed),
            tun_ingress_records: metrics.tun_ingress_records.load(Ordering::Relaxed),
            tun_ingress_bytes: metrics.tun_ingress_bytes.load(Ordering::Relaxed),
            gso_input_bytes: metrics.gso_input_bytes.load(Ordering::Relaxed),
            reassembly_pressure_evictions: metrics
                .reassembly_pressure_evictions
                .load(Ordering::Relaxed),
            train_build_bytes: metrics.record_bytes_built.load(Ordering::Relaxed),
            bulk_preemptions: metrics.bulk_preemptions.load(Ordering::Relaxed),
            bulk_preemption_delay_micros: metrics
                .bulk_preemption_delay_micros
                .load(Ordering::Relaxed),
            utility_tx_bytes,
            latency_sojourn: std::array::from_fn(|index| {
                metrics.latency_sojourn_buckets[index].load(Ordering::Relaxed)
            }),
        }
    }

    pub(super) fn saturating_delta(self, previous: Self) -> SampleCounterDelta {
        SampleCounterDelta {
            real_bytes: self.real_bytes.saturating_sub(previous.real_bytes),
            tun_ingress_records: self
                .tun_ingress_records
                .saturating_sub(previous.tun_ingress_records),
            tun_ingress_bytes: self
                .tun_ingress_bytes
                .saturating_sub(previous.tun_ingress_bytes),
            gso_input_bytes: self
                .gso_input_bytes
                .saturating_sub(previous.gso_input_bytes),
            reassembly_pressure_evictions: self
                .reassembly_pressure_evictions
                .saturating_sub(previous.reassembly_pressure_evictions),
            train_build_bytes: self
                .train_build_bytes
                .saturating_sub(previous.train_build_bytes),
            bulk_preemptions: self
                .bulk_preemptions
                .saturating_sub(previous.bulk_preemptions),
            bulk_preemption_delay_micros: self
                .bulk_preemption_delay_micros
                .saturating_sub(previous.bulk_preemption_delay_micros),
            latency_sojourn: std::array::from_fn(|index| {
                self.latency_sojourn[index].saturating_sub(previous.latency_sojourn[index])
            }),
        }
    }
}

/// Counters emitted by the periodic status line. The timestamp and every
/// baseline move together only after that line has been published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StatusCounterSnapshot {
    pub(super) at: Instant,
    pub(super) tx_bytes: TxByteSnapshotV2,
    pub(super) real_bytes: u64,
    pub(super) tun_ingress_records: u64,
    pub(super) tun_ingress_bytes: u64,
    pub(super) gso_input_bytes: u64,
    pub(super) cover_bytes: u64,
    pub(super) data_cell_bytes: u64,
    pub(super) data_cell_payload_bytes: u64,
    pub(super) fec_bytes: u64,
    pub(super) trains_built: u64,
    pub(super) records_built: u64,
    pub(super) record_bytes_built: u64,
    pub(super) cells_built: u64,
    pub(super) cell_payload_built_bytes: u64,
    pub(super) unused_cell_capacity_bytes: u64,
    pub(super) fec_parity_rx: u64,
    pub(super) fec_recovered_cells: u64,
    pub(super) fec_wasted_parity: u64,
    pub(super) repair_received_cells: u64,
    pub(super) repair_completed_requests: u64,
    pub(super) repair_completed_requested_cells: u64,
    pub(super) repair_latency_micros: u64,
    pub(super) bulk_service_bytes: u64,
    pub(super) latency_service_bytes: u64,
    pub(super) bulk_preemptions: u64,
    pub(super) bulk_preemption_delay_micros: u64,
    pub(super) latency_sojourn: [u64; LATENCY_SOJOURN_BUCKETS],
    pub(super) bulk_flow_service: [u64; BULK_FAIRNESS_BUCKETS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StatusCounterDelta {
    pub(super) tx_bytes: TxByteSnapshotV2,
    pub(super) real_bytes: u64,
    pub(super) tun_ingress_records: u64,
    pub(super) tun_ingress_bytes: u64,
    pub(super) gso_input_bytes: u64,
    pub(super) cover_bytes: u64,
    pub(super) data_cell_bytes: u64,
    pub(super) data_cell_payload_bytes: u64,
    pub(super) fec_bytes: u64,
    pub(super) trains_built: u64,
    pub(super) records_built: u64,
    pub(super) record_bytes_built: u64,
    pub(super) cells_built: u64,
    pub(super) cell_payload_built_bytes: u64,
    pub(super) unused_cell_capacity_bytes: u64,
    pub(super) fec_parity_rx: u64,
    pub(super) fec_recovered_cells: u64,
    pub(super) fec_wasted_parity: u64,
    pub(super) repair_received_cells: u64,
    pub(super) repair_completed_requests: u64,
    pub(super) repair_completed_requested_cells: u64,
    pub(super) repair_latency_micros: u64,
    pub(super) bulk_service_bytes: u64,
    pub(super) latency_service_bytes: u64,
    pub(super) bulk_preemptions: u64,
    pub(super) bulk_preemption_delay_micros: u64,
    pub(super) latency_sojourn: [u64; LATENCY_SOJOURN_BUCKETS],
    pub(super) bulk_flow_service: [u64; BULK_FAIRNESS_BUCKETS],
}

impl StatusCounterSnapshot {
    pub(super) fn capture(
        metrics: &RuntimeMetrics,
        udp_tx_bytes: u64,
        real_bytes: u64,
        at: Instant,
    ) -> Self {
        Self::capture_with_tx(
            metrics,
            TxByteSnapshotV2::load(metrics, udp_tx_bytes),
            real_bytes,
            at,
        )
    }

    pub(super) fn capture_with_tx(
        metrics: &RuntimeMetrics,
        tx_bytes: TxByteSnapshotV2,
        real_bytes: u64,
        at: Instant,
    ) -> Self {
        Self {
            at,
            tx_bytes,
            real_bytes,
            tun_ingress_records: metrics.tun_ingress_records.load(Ordering::Relaxed),
            tun_ingress_bytes: metrics.tun_ingress_bytes.load(Ordering::Relaxed),
            gso_input_bytes: metrics.gso_input_bytes.load(Ordering::Relaxed),
            cover_bytes: metrics.cover_tx_bytes.load(Ordering::Relaxed),
            data_cell_bytes: metrics.data_cell_tx_bytes.load(Ordering::Relaxed),
            data_cell_payload_bytes: metrics.data_cell_payload_tx_bytes.load(Ordering::Relaxed),
            fec_bytes: metrics.fec_tx_bytes.load(Ordering::Relaxed),
            trains_built: metrics.trains_built.load(Ordering::Relaxed),
            records_built: metrics.records_built.load(Ordering::Relaxed),
            record_bytes_built: metrics.record_bytes_built.load(Ordering::Relaxed),
            cells_built: metrics.cells_built.load(Ordering::Relaxed),
            cell_payload_built_bytes: metrics.cell_payload_built_bytes.load(Ordering::Relaxed),
            unused_cell_capacity_bytes: metrics.unused_cell_capacity_bytes.load(Ordering::Relaxed),
            fec_parity_rx: metrics.fec_parity_rx.load(Ordering::Relaxed),
            fec_recovered_cells: metrics.fec_recovered_cells.load(Ordering::Relaxed),
            fec_wasted_parity: metrics.fec_wasted_parity.load(Ordering::Relaxed),
            repair_received_cells: metrics.repair_received_cells.load(Ordering::Relaxed),
            repair_completed_requests: metrics.repair_completed_requests.load(Ordering::Relaxed),
            repair_completed_requested_cells: metrics
                .repair_completed_requested_cells
                .load(Ordering::Relaxed),
            repair_latency_micros: metrics.repair_latency_micros.load(Ordering::Relaxed),
            bulk_service_bytes: metrics.bulk_service_bytes.load(Ordering::Relaxed),
            latency_service_bytes: metrics.latency_service_bytes.load(Ordering::Relaxed),
            bulk_preemptions: metrics.bulk_preemptions.load(Ordering::Relaxed),
            bulk_preemption_delay_micros: metrics
                .bulk_preemption_delay_micros
                .load(Ordering::Relaxed),
            latency_sojourn: std::array::from_fn(|index| {
                metrics.latency_sojourn_buckets[index].load(Ordering::Relaxed)
            }),
            bulk_flow_service: std::array::from_fn(|index| {
                metrics.bulk_flow_service[index].load(Ordering::Relaxed)
            }),
        }
    }

    pub(super) fn saturating_delta(self, previous: Self) -> StatusCounterDelta {
        StatusCounterDelta {
            tx_bytes: self.tx_bytes.delta(previous.tx_bytes),
            real_bytes: self.real_bytes.saturating_sub(previous.real_bytes),
            tun_ingress_records: self
                .tun_ingress_records
                .saturating_sub(previous.tun_ingress_records),
            tun_ingress_bytes: self
                .tun_ingress_bytes
                .saturating_sub(previous.tun_ingress_bytes),
            gso_input_bytes: self
                .gso_input_bytes
                .saturating_sub(previous.gso_input_bytes),
            cover_bytes: self.cover_bytes.saturating_sub(previous.cover_bytes),
            data_cell_bytes: self
                .data_cell_bytes
                .saturating_sub(previous.data_cell_bytes),
            data_cell_payload_bytes: self
                .data_cell_payload_bytes
                .saturating_sub(previous.data_cell_payload_bytes),
            fec_bytes: self.fec_bytes.saturating_sub(previous.fec_bytes),
            trains_built: self.trains_built.saturating_sub(previous.trains_built),
            records_built: self.records_built.saturating_sub(previous.records_built),
            record_bytes_built: self
                .record_bytes_built
                .saturating_sub(previous.record_bytes_built),
            cells_built: self.cells_built.saturating_sub(previous.cells_built),
            cell_payload_built_bytes: self
                .cell_payload_built_bytes
                .saturating_sub(previous.cell_payload_built_bytes),
            unused_cell_capacity_bytes: self
                .unused_cell_capacity_bytes
                .saturating_sub(previous.unused_cell_capacity_bytes),
            fec_parity_rx: self.fec_parity_rx.saturating_sub(previous.fec_parity_rx),
            fec_recovered_cells: self
                .fec_recovered_cells
                .saturating_sub(previous.fec_recovered_cells),
            fec_wasted_parity: self
                .fec_wasted_parity
                .saturating_sub(previous.fec_wasted_parity),
            repair_received_cells: self
                .repair_received_cells
                .saturating_sub(previous.repair_received_cells),
            repair_completed_requests: self
                .repair_completed_requests
                .saturating_sub(previous.repair_completed_requests),
            repair_completed_requested_cells: self
                .repair_completed_requested_cells
                .saturating_sub(previous.repair_completed_requested_cells),
            repair_latency_micros: self
                .repair_latency_micros
                .saturating_sub(previous.repair_latency_micros),
            bulk_service_bytes: self
                .bulk_service_bytes
                .saturating_sub(previous.bulk_service_bytes),
            latency_service_bytes: self
                .latency_service_bytes
                .saturating_sub(previous.latency_service_bytes),
            bulk_preemptions: self
                .bulk_preemptions
                .saturating_sub(previous.bulk_preemptions),
            bulk_preemption_delay_micros: self
                .bulk_preemption_delay_micros
                .saturating_sub(previous.bulk_preemption_delay_micros),
            latency_sojourn: std::array::from_fn(|index| {
                self.latency_sojourn[index].saturating_sub(previous.latency_sojourn[index])
            }),
            bulk_flow_service: std::array::from_fn(|index| {
                self.bulk_flow_service[index].saturating_sub(previous.bulk_flow_service[index])
            }),
        }
    }
}

/// Receiver feedback is published asynchronously. Sequence and counters are a
/// single window, so a stale sequence leaves every derived remote metric intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RemoteFeedbackSnapshot {
    pub(super) sequence: u64,
    pub(super) at: Instant,
    pub(super) fec_parity: u64,
    pub(super) fec_recovered: u64,
    pub(super) fec_wasted: u64,
    pub(super) repair_received: u64,
    pub(super) repair_completed: u64,
    pub(super) repair_completed_requested: u64,
    pub(super) repair_latency_micros: u64,
    pub(super) delivered_payload: u64,
    pub(super) reorder_cells: u64,
    pub(super) missing_cells: u64,
    pub(super) loss_run_1: u64,
    pub(super) loss_run_2: u64,
    pub(super) loss_run_3_4: u64,
    pub(super) loss_run_5_plus: u64,
    pub(super) expired_trains: u64,
    pub(super) sent_data_cells: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RemoteFeedbackDelta {
    pub(super) fec_parity: u64,
    pub(super) fec_recovered: u64,
    pub(super) fec_wasted: u64,
    pub(super) repair_received: u64,
    pub(super) repair_completed: u64,
    pub(super) repair_completed_requested: u64,
    pub(super) repair_latency_micros: u64,
    pub(super) delivered_payload: u64,
    pub(super) reorder_cells: u64,
    pub(super) missing_cells: u64,
    pub(super) loss_run_1: u64,
    pub(super) loss_run_2: u64,
    pub(super) loss_run_3_4: u64,
    pub(super) loss_run_5_plus: u64,
    pub(super) expired_trains: u64,
    pub(super) sent_data_cells: u64,
}

impl RemoteFeedbackSnapshot {
    pub(super) fn capture(metrics: &RuntimeMetrics, sequence: u64, at: Instant) -> Self {
        Self {
            sequence,
            at,
            fec_parity: metrics.remote_fec_parity_rx.load(Ordering::Relaxed),
            fec_recovered: metrics.remote_fec_recovered_cells.load(Ordering::Relaxed),
            fec_wasted: metrics.remote_fec_wasted_parity.load(Ordering::Relaxed),
            repair_received: metrics.remote_repair_received_cells.load(Ordering::Relaxed),
            repair_completed: metrics
                .remote_repair_completed_requests
                .load(Ordering::Relaxed),
            repair_completed_requested: metrics
                .remote_repair_completed_requested_cells
                .load(Ordering::Relaxed),
            repair_latency_micros: metrics.remote_repair_latency_micros.load(Ordering::Relaxed),
            delivered_payload: metrics
                .remote_delivered_payload_bytes
                .load(Ordering::Relaxed),
            reorder_cells: metrics.remote_reorder_cells.load(Ordering::Relaxed),
            missing_cells: metrics.remote_missing_cells.load(Ordering::Relaxed),
            loss_run_1: metrics.remote_loss_run_1.load(Ordering::Relaxed),
            loss_run_2: metrics.remote_loss_run_2.load(Ordering::Relaxed),
            loss_run_3_4: metrics.remote_loss_run_3_4.load(Ordering::Relaxed),
            loss_run_5_plus: metrics.remote_loss_run_5_plus.load(Ordering::Relaxed),
            expired_trains: metrics
                .remote_reassembly_expired_trains
                .load(Ordering::Relaxed),
            sent_data_cells: metrics.data_cell_tx_datagrams.load(Ordering::Relaxed),
        }
    }

    pub(super) fn counter_delta(self, previous: Self) -> RemoteFeedbackDelta {
        RemoteFeedbackDelta {
            fec_parity: counter_delta(self.fec_parity, previous.fec_parity),
            fec_recovered: counter_delta(self.fec_recovered, previous.fec_recovered),
            fec_wasted: counter_delta(self.fec_wasted, previous.fec_wasted),
            repair_received: counter_delta(self.repair_received, previous.repair_received),
            repair_completed: counter_delta(self.repair_completed, previous.repair_completed),
            repair_completed_requested: counter_delta(
                self.repair_completed_requested,
                previous.repair_completed_requested,
            ),
            repair_latency_micros: counter_delta(
                self.repair_latency_micros,
                previous.repair_latency_micros,
            ),
            delivered_payload: counter_delta(self.delivered_payload, previous.delivered_payload),
            reorder_cells: counter_delta(self.reorder_cells, previous.reorder_cells),
            missing_cells: counter_delta(self.missing_cells, previous.missing_cells),
            loss_run_1: counter_delta(self.loss_run_1, previous.loss_run_1),
            loss_run_2: counter_delta(self.loss_run_2, previous.loss_run_2),
            loss_run_3_4: counter_delta(self.loss_run_3_4, previous.loss_run_3_4),
            loss_run_5_plus: counter_delta(self.loss_run_5_plus, previous.loss_run_5_plus),
            expired_trains: counter_delta(self.expired_trains, previous.expired_trains),
            sent_data_cells: counter_delta(self.sent_data_cells, previous.sent_data_cells),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct TunIngressBatchV2 {
    records: u64,
    bytes: u64,
    gso: GsoObservationV2,
}

impl TunIngressBatchV2 {
    pub(super) fn observe(&mut self, bytes: usize, gso: GsoObservationV2) {
        self.records = self.records.saturating_add(1);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        self.gso.input_bytes = self.gso.input_bytes.saturating_add(gso.input_bytes);
        self.gso.preserved_bytes = self.gso.preserved_bytes.saturating_add(gso.preserved_bytes);
        self.gso.fallback_splits = self.gso.fallback_splits.saturating_add(gso.fallback_splits);
    }
}

impl RuntimeMetrics {
    /// Capture every peer-facing atomic at one status-publication boundary.
    /// The configured TUN MTU is runtime state rather than an atomic counter,
    /// so the caller carries it forward from the peer's stable projection.
    pub(super) fn traffic_snapshot(&self, tun_mtu: u64) -> crate::status::PeerTrafficStatus {
        crate::status::PeerTrafficStatus {
            tx_packets: self.tun_ingress_records.load(Ordering::Relaxed),
            tx_bytes: self.tun_ingress_bytes.load(Ordering::Relaxed),
            rx_packets: self.tun_rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.tun_rx_bytes.load(Ordering::Relaxed),
            trains_built: self.trains_built.load(Ordering::Relaxed),
            cells_built: self.cells_built.load(Ordering::Relaxed),
            data_cell_tx_datagrams: self.data_cell_tx_datagrams.load(Ordering::Relaxed),
            full_payload_cells_built: self.full_payload_cells_built.load(Ordering::Relaxed),
            data_cell_tx_bytes: self.data_cell_tx_bytes.load(Ordering::Relaxed),
            cell_payload_tx_bytes: self.data_cell_payload_tx_bytes.load(Ordering::Relaxed),
            unused_cell_capacity_bytes: self.unused_cell_capacity_bytes.load(Ordering::Relaxed),
            split_records_built: self.split_records_built.load(Ordering::Relaxed),
            fec_tx_cells: self.fec_parity_cells_built.load(Ordering::Relaxed),
            fec_tx_bytes: self.fec_tx_bytes.load(Ordering::Relaxed),
            fec_rx_cells: self.fec_parity_rx.load(Ordering::Relaxed),
            fec_recovered_cells: self.fec_recovered_cells.load(Ordering::Relaxed),
            fec_wasted_cells: self.fec_wasted_parity.load(Ordering::Relaxed),
            fec_expired_stripes: self.fec_expired_stripes.load(Ordering::Relaxed),
            fec_unprotected_tail_cells: self.fec_unprotected_tail_cells.load(Ordering::Relaxed),
            fec_encode_copy_bytes: self.fec_encode_copy_bytes.load(Ordering::Relaxed),
            fec_decode_copy_bytes: self.fec_decode_copy_bytes.load(Ordering::Relaxed),
            repair_requested_cells: self.repair_requested_cells.load(Ordering::Relaxed),
            repair_suppressed_stripes: self.repair_suppressed_stripes.load(Ordering::Relaxed),
            repair_suppressed_cells: self.repair_suppressed_cells.load(Ordering::Relaxed),
            repair_received_cells: self.repair_received_cells.load(Ordering::Relaxed),
            repair_completed_requests: self.repair_completed_requests.load(Ordering::Relaxed),
            repair_latency_max_micros: self.repair_latency_max_micros.load(Ordering::Relaxed),
            repair_stale_responses: self.repair_stale_responses.load(Ordering::Relaxed),
            bulk_service_bytes: self.bulk_service_bytes.load(Ordering::Relaxed),
            latency_service_bytes: self.latency_service_bytes.load(Ordering::Relaxed),
            bulk_preemptions: self.bulk_preemptions.load(Ordering::Relaxed),
            packet_train_queue_bytes: self.train_queue_bytes.load(Ordering::Relaxed),
            latency_queue_bytes: self.latency_queue_bytes.load(Ordering::Relaxed),
            receive_buffer_bytes: self.receive_buffer_bytes.load(Ordering::Relaxed),
            cover_tx_bytes: self.cover_tx_bytes.load(Ordering::Relaxed),
            cover_rx_bytes: self.cover_rx_bytes.load(Ordering::Relaxed),
            control_tx_bytes: self.control_record_tx_bytes.load(Ordering::Relaxed),
            control_rx_bytes: self.control_record_rx_bytes.load(Ordering::Relaxed),
            protocol_datagram_errors: self.protocol_datagram_errors.load(Ordering::Relaxed),
            route_gate_drops: self.route_gate_drops.load(Ordering::Relaxed),
            route_switches: self.route_switches.load(Ordering::Relaxed),
            tun_admission_drop_records: self.tun_admission_drop_records.load(Ordering::Relaxed),
            tun_admission_drop_bytes: self.tun_admission_drop_bytes.load(Ordering::Relaxed),
            reassembly_pressure_evictions: self
                .reassembly_pressure_evictions
                .load(Ordering::Relaxed),
            pmtu_drop_datagrams: self.pmtu_drop_datagrams.load(Ordering::Relaxed),
            pmtu_drop_bytes: self.pmtu_drop_bytes.load(Ordering::Relaxed),
            gso_input_bytes: self.gso_input_bytes.load(Ordering::Relaxed),
            gso_preserved_bytes: self.gso_preserved_bytes.load(Ordering::Relaxed),
            gso_fallback_splits: self.gso_fallback_splits.load(Ordering::Relaxed),
            tun_mtu,
        }
    }

    pub(super) fn record_protocol_datagram_error(&self) -> (u64, bool) {
        increment_sampled_counter(&self.protocol_datagram_errors)
    }

    pub(super) fn record_route_gate_drop(&self) -> (u64, bool) {
        increment_sampled_counter(&self.route_gate_drops)
    }

    pub(super) fn observe_tun_ingress_batch(&self, observation: TunIngressBatchV2) {
        if observation.records == 0 {
            return;
        }
        self.tun_ingress_records
            .fetch_add(observation.records, Ordering::Relaxed);
        self.tun_ingress_bytes
            .fetch_add(observation.bytes, Ordering::Relaxed);
        self.gso_input_bytes
            .fetch_add(observation.gso.input_bytes, Ordering::Relaxed);
        self.gso_preserved_bytes
            .fetch_add(observation.gso.preserved_bytes, Ordering::Relaxed);
        self.gso_fallback_splits
            .fetch_add(observation.gso.fallback_splits, Ordering::Relaxed);
    }

    pub(super) fn observe_bulk_admission(&self, bytes: u64) {
        self.bulk_admission_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub(super) fn observe_send(&self, progress: SendProgress) {
        if let Some(class) = progress.class {
            match class {
                TrafficClass::Latency => {
                    self.latency_service_bytes
                        .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    self.latency_service_quantums
                        .fetch_add(1, Ordering::Relaxed);
                    let bucket = latency_sojourn_bucket(progress.queue_sojourn_micros);
                    self.latency_sojourn_buckets[bucket].fetch_add(1, Ordering::Relaxed);
                    if progress.bulk_preemption {
                        self.bulk_preemptions.fetch_add(1, Ordering::Relaxed);
                        self.bulk_preemption_delay_micros
                            .fetch_add(progress.queue_sojourn_micros, Ordering::Relaxed);
                        self.bulk_preemption_max_delay_micros
                            .fetch_max(progress.queue_sojourn_micros, Ordering::Relaxed);
                    }
                }
                TrafficClass::Bulk => {
                    self.bulk_service_bytes
                        .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    self.bulk_service_quantums.fetch_add(1, Ordering::Relaxed);
                    if let Some(flow_id) = progress.flow_id {
                        self.bulk_flow_service[flow_id as usize % BULK_FAIRNESS_BUCKETS]
                            .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    }
                }
            }
        }
        self.data_cell_tx_datagrams
            .fetch_add(progress.data_cell_datagrams as u64, Ordering::Relaxed);
        self.data_cell_tx_bytes
            .fetch_add(progress.data_cell_bytes as u64, Ordering::Relaxed);
        self.data_cell_payload_tx_bytes
            .fetch_add(progress.data_cell_payload_bytes as u64, Ordering::Relaxed);
        self.fec_tx_datagrams
            .fetch_add(progress.fec_datagrams as u64, Ordering::Relaxed);
        self.fec_tx_bytes
            .fetch_add(progress.fec_bytes as u64, Ordering::Relaxed);
        if let Some(stats) = progress.train_stats {
            self.trains_built.fetch_add(1, Ordering::Relaxed);
            self.records_built
                .fetch_add(stats.records, Ordering::Relaxed);
            self.record_bytes_built
                .fetch_add(stats.record_bytes, Ordering::Relaxed);
            self.split_records_built
                .fetch_add(stats.split_records, Ordering::Relaxed);
            self.cells_built.fetch_add(stats.cells, Ordering::Relaxed);
            self.full_payload_cells_built
                .fetch_add(stats.full_payload_cells, Ordering::Relaxed);
            self.cell_payload_built_bytes
                .fetch_add(stats.cell_payload_bytes, Ordering::Relaxed);
            self.cell_wire_built_bytes
                .fetch_add(stats.cell_wire_bytes, Ordering::Relaxed);
            self.unused_cell_capacity_bytes
                .fetch_add(stats.unused_payload_capacity, Ordering::Relaxed);
            self.fec_stripes_built
                .fetch_add(stats.fec_stripes, Ordering::Relaxed);
            self.fec_protected_data_cells
                .fetch_add(stats.fec_protected_data_cells, Ordering::Relaxed);
            self.fec_parity_cells_built
                .fetch_add(stats.fec_parity_cells, Ordering::Relaxed);
            self.fec_encode_copy_bytes
                .fetch_add(stats.fec_encode_copy_bytes, Ordering::Relaxed);
            self.fec_unprotected_tail_cells
                .fetch_add(stats.fec_unprotected_tail_cells, Ordering::Relaxed);
        }
    }

    pub(super) fn observe_control_tx(&self, record: &[u8]) {
        self.observe_control_record(
            record,
            &self.control_record_tx_bytes,
            &self.repair_request_tx_bytes,
            &self.repair_response_tx_bytes,
        );
    }

    pub(super) fn observe_control_rx(&self, record: &[u8]) {
        self.observe_control_record(
            record,
            &self.control_record_rx_bytes,
            &self.repair_request_rx_bytes,
            &self.repair_response_rx_bytes,
        );
    }

    pub(super) fn observe_control_record(
        &self,
        record: &[u8],
        total: &AtomicU64,
        repair_requests: &AtomicU64,
        repair_responses: &AtomicU64,
    ) {
        let bytes = u64::try_from(record.len()).unwrap_or(u64::MAX);
        total.fetch_add(bytes, Ordering::Relaxed);
        if RepairControlV2::is_request(record) {
            repair_requests.fetch_add(bytes, Ordering::Relaxed);
        } else if RepairControlV2::is_response(record) {
            repair_responses.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(super) fn observe_receive(&self, output: &ReassemblyOutput) {
        self.reassembly_pressure_evictions
            .fetch_add(output.pressure_evicted_trains, Ordering::Relaxed);
        self.reassembly_expired_trains
            .fetch_add(output.reassembly_expired_trains, Ordering::Relaxed);
        self.reorder_cells
            .fetch_add(output.reorder_cells, Ordering::Relaxed);
        self.missing_cells
            .fetch_add(output.missing_cells, Ordering::Relaxed);
        self.fec_parity_rx
            .fetch_add(output.fec.parity_received, Ordering::Relaxed);
        self.fec_recovered_cells
            .fetch_add(output.fec.recovered_cells, Ordering::Relaxed);
        self.fec_wasted_parity
            .fetch_add(output.fec.wasted_parity, Ordering::Relaxed);
        self.fec_expired_stripes
            .fetch_add(output.fec.expired_stripes, Ordering::Relaxed);
        self.fec_decode_copy_bytes
            .fetch_add(output.fec.decode_copy_bytes, Ordering::Relaxed);
        self.fec_recovery_latency_micros
            .fetch_add(output.fec.recovery_latency_micros, Ordering::Relaxed);
    }

    pub(super) fn observe_repair_request(&self, request: &RepairRequestV2) {
        self.repair_requested_cells
            .fetch_add(request.missing_sequences.len() as u64, Ordering::Relaxed);
        let runs = LossRunHistogramV2::from_missing_sequences(&request.missing_sequences);
        self.loss_run_1.fetch_add(runs.run_1, Ordering::Relaxed);
        self.loss_run_2.fetch_add(runs.run_2, Ordering::Relaxed);
        self.loss_run_3_4.fetch_add(runs.run_3_4, Ordering::Relaxed);
        self.loss_run_5_plus
            .fetch_add(runs.run_5_plus, Ordering::Relaxed);
    }

    pub(super) fn observe_repair_suppression(&self, batch: &RepairRequestBatchV2) {
        self.repair_suppressed_stripes
            .fetch_add(batch.suppressed_stripes, Ordering::Relaxed);
        self.repair_suppressed_cells
            .fetch_add(batch.suppressed_cells, Ordering::Relaxed);
    }

    pub(super) fn observe_local_delivery(&self, output: &ReassemblyOutput) {
        if output.records.is_empty() {
            return;
        }
        let bytes = output.records.iter().fold(0_u64, |total, record| {
            total.saturating_add(u64::try_from(record.total_len).unwrap_or(u64::MAX))
        });
        self.tun_rx_packets.fetch_add(
            u64::try_from(output.records.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.tun_rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(super) fn observe_repair_response(&self, observation: RepairResponseObservationV2) {
        self.repair_received_cells
            .fetch_add(observation.received_cells, Ordering::Relaxed);
        self.repair_completed_requests
            .fetch_add(1, Ordering::Relaxed);
        self.repair_completed_requested_cells
            .fetch_add(observation.requested_cells, Ordering::Relaxed);
        self.repair_latency_micros
            .fetch_add(observation.latency_micros, Ordering::Relaxed);
        self.repair_latency_max_micros
            .fetch_max(observation.latency_micros, Ordering::Relaxed);
    }

    pub(super) fn fec_feedback(&self, sequence: u64) -> FecFeedbackV2 {
        FecFeedbackV2 {
            sequence,
            parity_received: self.fec_parity_rx.load(Ordering::Relaxed),
            recovered_cells: self.fec_recovered_cells.load(Ordering::Relaxed),
            wasted_parity: self.fec_wasted_parity.load(Ordering::Relaxed),
            repair_requested_cells: self.repair_requested_cells.load(Ordering::Relaxed),
            repair_received_cells: self.repair_received_cells.load(Ordering::Relaxed),
            repair_completed_requests: self.repair_completed_requests.load(Ordering::Relaxed),
            repair_completed_requested_cells: self
                .repair_completed_requested_cells
                .load(Ordering::Relaxed),
            repair_latency_micros: self.repair_latency_micros.load(Ordering::Relaxed),
            expired_stripes: self.fec_expired_stripes.load(Ordering::Relaxed),
            delivered_payload_bytes: self.tun_rx_bytes.load(Ordering::Relaxed),
            reorder_cells: self.reorder_cells.load(Ordering::Relaxed),
            missing_cells: self.missing_cells.load(Ordering::Relaxed),
            loss_run_1: self.loss_run_1.load(Ordering::Relaxed),
            loss_run_2: self.loss_run_2.load(Ordering::Relaxed),
            loss_run_3_4: self.loss_run_3_4.load(Ordering::Relaxed),
            loss_run_5_plus: self.loss_run_5_plus.load(Ordering::Relaxed),
            reassembly_expired_trains: self.reassembly_expired_trains.load(Ordering::Relaxed),
        }
    }

    pub(super) fn apply_remote_feedback(&self, feedback: FecFeedbackV2) -> bool {
        if feedback.sequence <= self.remote_feedback_sequence.load(Ordering::Acquire) {
            return false;
        }
        self.remote_fec_parity_rx
            .store(feedback.parity_received, Ordering::Relaxed);
        self.remote_fec_recovered_cells
            .store(feedback.recovered_cells, Ordering::Relaxed);
        self.remote_fec_wasted_parity
            .store(feedback.wasted_parity, Ordering::Relaxed);
        self.remote_fec_expired_stripes
            .store(feedback.expired_stripes, Ordering::Relaxed);
        self.remote_repair_requested_cells
            .store(feedback.repair_requested_cells, Ordering::Relaxed);
        self.remote_repair_received_cells
            .store(feedback.repair_received_cells, Ordering::Relaxed);
        self.remote_repair_completed_requests
            .store(feedback.repair_completed_requests, Ordering::Relaxed);
        self.remote_repair_completed_requested_cells
            .store(feedback.repair_completed_requested_cells, Ordering::Relaxed);
        self.remote_repair_latency_micros
            .store(feedback.repair_latency_micros, Ordering::Relaxed);
        self.remote_delivered_payload_bytes
            .store(feedback.delivered_payload_bytes, Ordering::Relaxed);
        self.remote_reorder_cells
            .store(feedback.reorder_cells, Ordering::Relaxed);
        self.remote_missing_cells
            .store(feedback.missing_cells, Ordering::Relaxed);
        self.remote_loss_run_1
            .store(feedback.loss_run_1, Ordering::Relaxed);
        self.remote_loss_run_2
            .store(feedback.loss_run_2, Ordering::Relaxed);
        self.remote_loss_run_3_4
            .store(feedback.loss_run_3_4, Ordering::Relaxed);
        self.remote_loss_run_5_plus
            .store(feedback.loss_run_5_plus, Ordering::Relaxed);
        self.remote_reassembly_expired_trains
            .store(feedback.reassembly_expired_trains, Ordering::Relaxed);
        self.remote_feedback_sequence
            .store(feedback.sequence, Ordering::Release);
        true
    }
}

/// Increment a cumulative metric while requesting logs only at powers of two.
/// This keeps the first error visible, then bounds a sustained attack to
/// O(log n) messages without hiding the exact cumulative count.
pub(super) fn increment_sampled_counter(counter: &AtomicU64) -> (u64, bool) {
    let count = counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    (count, count.is_power_of_two())
}

fn latency_sojourn_bucket(micros: u64) -> usize {
    LATENCY_SOJOURN_UPPER_MICROS
        .iter()
        .position(|upper| micros <= *upper)
        .unwrap_or(LATENCY_SOJOURN_BUCKETS - 1)
}

pub(super) fn histogram_percentile_micros(
    delta: &[u64; LATENCY_SOJOURN_BUCKETS],
    percentile: u64,
) -> u64 {
    let total = delta.iter().copied().sum::<u64>();
    if total == 0 {
        return 0;
    }
    let target = total
        .saturating_mul(percentile)
        .saturating_add(99)
        .saturating_div(100)
        .max(1);
    let mut cumulative = 0_u64;
    for (index, count) in delta.iter().copied().enumerate() {
        cumulative = cumulative.saturating_add(count);
        if cumulative >= target {
            return LATENCY_SOJOURN_UPPER_MICROS
                .get(index)
                .copied()
                .unwrap_or(1_000_001);
        }
    }
    1_000_001
}

pub(super) fn jain_fairness_ppm(service: &[u64; BULK_FAIRNESS_BUCKETS]) -> u64 {
    let active = service.iter().filter(|bytes| **bytes != 0).count() as u128;
    if active <= 1 {
        return if active == 0 { 0 } else { 1_000_000 };
    }
    let sum = service.iter().copied().map(u128::from).sum::<u128>();
    let squares = service
        .iter()
        .copied()
        .map(u128::from)
        .map(|value| value.saturating_mul(value))
        .sum::<u128>();
    sum.saturating_mul(sum)
        .saturating_mul(1_000_000)
        .checked_div(active.saturating_mul(squares))
        .unwrap_or_default()
        .min(1_000_000) as u64
}

pub(super) fn counter_delta(current: u64, previous: u64) -> u64 {
    // Per-path QUIC counters can restart when noq refreshes a path object even
    // though the semantic remote locator and logical session are unchanged.
    // Treat the new counter as the first sample of that replacement instead
    // of manufacturing a zero-rate interval through saturating subtraction.
    current.checked_sub(previous).unwrap_or(current)
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::Ordering, time::Instant};

    use super::*;

    #[test]
    fn sample_counter_snapshot_delta_is_saturating_and_advance_is_atomic() {
        let metrics = RuntimeMetrics::default();
        metrics.real_tx_bytes.store(10, Ordering::Relaxed);
        metrics.tun_ingress_records.store(2, Ordering::Relaxed);
        metrics.tun_ingress_bytes.store(200, Ordering::Relaxed);
        metrics.latency_sojourn_buckets[3].store(4, Ordering::Relaxed);
        let previous = SampleCounterSnapshot::capture(&metrics, 1_000);

        metrics.real_tx_bytes.store(25, Ordering::Relaxed);
        metrics.tun_ingress_records.store(5, Ordering::Relaxed);
        metrics.tun_ingress_bytes.store(650, Ordering::Relaxed);
        metrics
            .reassembly_pressure_evictions
            .store(3, Ordering::Relaxed);
        metrics.latency_sojourn_buckets[3].store(9, Ordering::Relaxed);
        let current = SampleCounterSnapshot::capture(&metrics, 1_200);
        let delta = current.saturating_delta(previous);

        assert_eq!(delta.real_bytes, 15);
        assert_eq!(delta.tun_ingress_records, 3);
        assert_eq!(delta.tun_ingress_bytes, 450);
        assert_eq!(delta.reassembly_pressure_evictions, 3);
        assert_eq!(delta.latency_sojourn[3], 5);
        assert_eq!(current.utility_tx_bytes.quic_udp_payload_bytes, 1_200);

        let mut window = previous;
        assert_eq!(window.real_bytes, previous.real_bytes);
        window = current;
        metrics.real_tx_bytes.store(3, Ordering::Relaxed);
        let reset = SampleCounterSnapshot::capture(&metrics, 1_200);
        assert_eq!(reset.saturating_delta(window).real_bytes, 0);
    }

    #[test]
    fn status_counter_snapshot_delta_and_advance_keep_histograms_in_one_window() {
        let metrics = RuntimeMetrics::default();
        metrics.cover_tx_bytes.store(20, Ordering::Relaxed);
        metrics.data_cell_tx_bytes.store(100, Ordering::Relaxed);
        metrics.bulk_service_bytes.store(50, Ordering::Relaxed);
        metrics.latency_sojourn_buckets[2].store(1, Ordering::Relaxed);
        metrics.bulk_flow_service[1].store(4, Ordering::Relaxed);
        let previous = StatusCounterSnapshot::capture(&metrics, 1_000, 40, Instant::now());

        metrics.cover_tx_bytes.store(35, Ordering::Relaxed);
        metrics.data_cell_tx_bytes.store(180, Ordering::Relaxed);
        metrics.bulk_service_bytes.store(90, Ordering::Relaxed);
        metrics.latency_sojourn_buckets[2].store(6, Ordering::Relaxed);
        metrics.bulk_flow_service[1].store(10, Ordering::Relaxed);
        let current = StatusCounterSnapshot::capture(&metrics, 1_300, 64, Instant::now());
        let delta = current.saturating_delta(previous);

        assert_eq!(delta.tx_bytes.quic_udp_payload_bytes, 300);
        assert_eq!(delta.real_bytes, 24);
        assert_eq!(delta.cover_bytes, 15);
        assert_eq!(delta.data_cell_bytes, 80);
        assert_eq!(delta.bulk_service_bytes, 40);
        assert_eq!(delta.latency_sojourn[2], 5);
        assert_eq!(delta.bulk_flow_service[1], 6);

        let mut window = previous;
        assert_eq!(window.at, previous.at);
        window = current;
        metrics.cover_tx_bytes.store(3, Ordering::Relaxed);
        metrics.latency_sojourn_buckets[2].store(2, Ordering::Relaxed);
        let reset = StatusCounterSnapshot::capture(&metrics, 1_300, 1, Instant::now());
        assert_eq!(reset.saturating_delta(window).cover_bytes, 0);
        assert_eq!(reset.saturating_delta(window).real_bytes, 0);
        assert_eq!(reset.saturating_delta(window).latency_sojourn[2], 0);
    }

    #[test]
    fn remote_feedback_snapshot_uses_sequence_window_and_reset_safe_deltas() {
        let metrics = RuntimeMetrics::default();
        metrics.remote_fec_parity_rx.store(10, Ordering::Relaxed);
        metrics
            .remote_repair_completed_requests
            .store(4, Ordering::Relaxed);
        metrics.data_cell_tx_datagrams.store(20, Ordering::Relaxed);
        let previous = RemoteFeedbackSnapshot::capture(&metrics, 7, Instant::now());

        metrics.remote_fec_parity_rx.store(16, Ordering::Relaxed);
        metrics
            .remote_repair_completed_requests
            .store(9, Ordering::Relaxed);
        metrics.data_cell_tx_datagrams.store(32, Ordering::Relaxed);
        let current = RemoteFeedbackSnapshot::capture(&metrics, 8, Instant::now());
        let delta = current.counter_delta(previous);

        assert_eq!(delta.fec_parity, 6);
        assert_eq!(delta.repair_completed, 5);
        assert_eq!(delta.sent_data_cells, 12);

        let mut window = previous;
        assert_eq!(window.sequence, previous.sequence);
        window = current;
        metrics.remote_fec_parity_rx.store(3, Ordering::Relaxed);
        let reset = RemoteFeedbackSnapshot::capture(&metrics, 9, Instant::now());
        assert_eq!(reset.counter_delta(window).fec_parity, 3);
        assert_eq!(reset.sequence, 9);
    }

    #[test]
    fn control_byte_metrics_partition_repair_without_double_counting() {
        let metrics = RuntimeMetrics::default();
        metrics.observe_control_tx(b"FRQ2-request");
        metrics.observe_control_tx(b"FRS2-response-data");
        metrics.observe_control_tx(b"PRES-presence");
        metrics.observe_control_rx(b"FRQ2-rx");
        metrics.observe_control_rx(b"FRS2-rx-data");

        assert_eq!(
            metrics.control_record_tx_bytes.load(Ordering::Relaxed),
            12 + 18 + 13
        );
        assert_eq!(metrics.repair_request_tx_bytes.load(Ordering::Relaxed), 12);
        assert_eq!(metrics.repair_response_tx_bytes.load(Ordering::Relaxed), 18);
        assert_eq!(
            metrics.control_record_rx_bytes.load(Ordering::Relaxed),
            7 + 12
        );
        assert_eq!(metrics.repair_request_rx_bytes.load(Ordering::Relaxed), 7);
        assert_eq!(metrics.repair_response_rx_bytes.load(Ordering::Relaxed), 12);
    }

    #[test]
    fn tx_byte_ledger_separates_protocol_layers_and_boundary_lag() {
        let bytes = TxByteSnapshotV2 {
            quic_udp_payload_bytes: 2_000,
            real_record_bytes: 700,
            data_cell_bytes: 1_000,
            data_cell_payload_bytes: 800,
            fec_bytes: 200,
            control_record_bytes: 100,
            repair_request_bytes: 30,
            repair_response_bytes: 40,
            padding_bytes: 50,
        }
        .breakdown();
        assert_eq!(bytes.real_record_bytes, 700);
        assert_eq!(bytes.packet_train_metadata_bytes, 100);
        assert_eq!(bytes.cell_envelope_bytes, 200);
        assert_eq!(bytes.other_control_record_bytes, 30);
        assert_eq!(bytes.quic_transport_residual_bytes, 650);
        assert_eq!(bytes.interval_accounting_lag_bytes, 0);

        let lagged = TxByteSnapshotV2 {
            quic_udp_payload_bytes: 1_000,
            data_cell_bytes: 900,
            fec_bytes: 100,
            control_record_bytes: 50,
            padding_bytes: 25,
            ..TxByteSnapshotV2::default()
        }
        .breakdown();
        assert_eq!(lagged.quic_transport_residual_bytes, 0);
        assert_eq!(lagged.interval_accounting_lag_bytes, 75);
    }

    #[test]
    fn sustained_datagram_errors_are_counted_but_exponentially_sampled() {
        let metrics = RuntimeMetrics::default();
        let mut reported = Vec::new();
        for _ in 0..10 {
            let (count, report) = metrics.record_protocol_datagram_error();
            if report {
                reported.push(count);
            }
        }
        assert_eq!(reported, [1, 2, 4, 8]);
        assert_eq!(metrics.protocol_datagram_errors.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn tun_ingress_metrics_are_folded_once_per_admission_batch() {
        let metrics = RuntimeMetrics::default();
        let mut batch = TunIngressBatchV2::default();
        batch.observe(
            1_500,
            GsoObservationV2 {
                input_bytes: 0,
                preserved_bytes: 0,
                fallback_splits: 0,
            },
        );
        batch.observe(
            60_000,
            GsoObservationV2 {
                input_bytes: 60_000,
                preserved_bytes: 60_000,
                fallback_splits: 0,
            },
        );
        metrics.observe_tun_ingress_batch(batch);

        assert_eq!(metrics.tun_ingress_records.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.tun_ingress_bytes.load(Ordering::Relaxed), 61_500);
        assert_eq!(metrics.gso_input_bytes.load(Ordering::Relaxed), 60_000);
        assert_eq!(metrics.gso_preserved_bytes.load(Ordering::Relaxed), 60_000);
        assert_eq!(metrics.gso_fallback_splits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fec_feedback_is_monotonic_and_directional() {
        let metrics = RuntimeMetrics::default();
        let first = FecFeedbackV2 {
            sequence: 2,
            parity_received: 10,
            recovered_cells: 3,
            wasted_parity: 6,
            repair_requested_cells: 4,
            repair_received_cells: 3,
            repair_completed_requests: 2,
            repair_completed_requested_cells: 4,
            repair_latency_micros: 40_000,
            expired_stripes: 1,
            delivered_payload_bytes: 8_000_000,
            reorder_cells: 2,
            missing_cells: 3,
            loss_run_1: 1,
            loss_run_2: 1,
            loss_run_3_4: 0,
            loss_run_5_plus: 0,
            reassembly_expired_trains: 1,
        };
        assert!(metrics.apply_remote_feedback(first));
        assert!(!metrics.apply_remote_feedback(FecFeedbackV2 {
            sequence: 1,
            parity_received: 99,
            ..first
        }));
        assert_eq!(metrics.remote_feedback_sequence.load(Ordering::Acquire), 2);
        assert_eq!(metrics.remote_fec_parity_rx.load(Ordering::Relaxed), 10);
        assert_eq!(
            metrics.remote_fec_recovered_cells.load(Ordering::Relaxed),
            3
        );
        assert_eq!(metrics.fec_parity_rx.load(Ordering::Relaxed), 0);
        assert_eq!(
            metrics
                .remote_delivered_payload_bytes
                .load(Ordering::Relaxed),
            8_000_000
        );
        assert_eq!(metrics.remote_reorder_cells.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.remote_missing_cells.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.remote_loss_run_1.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .remote_reassembly_expired_trains
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .remote_repair_completed_requests
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics.remote_repair_latency_micros.load(Ordering::Relaxed),
            40_000
        );
        assert_eq!(
            metrics
                .remote_repair_completed_requested_cells
                .load(Ordering::Relaxed),
            4
        );
    }

    #[test]
    fn scheduler_observability_histogram_and_fairness_are_bounded() {
        assert_eq!(latency_sojourn_bucket(0), 0);
        assert_eq!(latency_sojourn_bucket(51), 1);
        assert_eq!(
            latency_sojourn_bucket(u64::MAX),
            LATENCY_SOJOURN_BUCKETS - 1
        );

        let mut histogram = [0_u64; LATENCY_SOJOURN_BUCKETS];
        histogram[0] = 50;
        histogram[5] = 45;
        histogram[LATENCY_SOJOURN_BUCKETS - 1] = 5;
        assert_eq!(histogram_percentile_micros(&histogram, 50), 50);
        assert_eq!(histogram_percentile_micros(&histogram, 95), 2_500);
        assert_eq!(histogram_percentile_micros(&histogram, 99), 1_000_001);

        let mut service = [0_u64; BULK_FAIRNESS_BUCKETS];
        service[0] = 100;
        service[1] = 50;
        assert_eq!(jain_fairness_ppm(&service), 900_000);
        service[1] = 100;
        assert_eq!(jain_fairness_ppm(&service), 1_000_000);
    }
}
