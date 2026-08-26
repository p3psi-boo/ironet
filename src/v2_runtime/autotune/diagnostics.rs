//! Bounded operational diagnostics for the autotune loop.

use super::*;

/// Emits the bounded operational view once per ten policy samples. The full
/// counter inventory remains in `RuntimeMetrics` and the status API; this log
/// intentionally carries the decisions and pressure signals an operator needs
/// to diagnose a live path without duplicating that inventory in the ticker.
pub(crate) struct PeriodicStatus<'a> {
    pub(crate) peer: EndpointId,
    pub(crate) decision: TuneDecisionV2,
    pub(crate) telemetry: PathTelemetryV2,
    pub(crate) metrics: &'a RuntimeMetrics,
    pub(crate) previous: &'a mut StatusCounterSnapshot,
    pub(crate) udp_tx_bytes: u64,
    pub(crate) real_bytes: u64,
    pub(crate) ticket_partition: &'a str,
}

pub(crate) fn emit_periodic_status(status: PeriodicStatus<'_>) {
    let PeriodicStatus {
        peer,
        decision,
        telemetry,
        metrics,
        previous,
        udp_tx_bytes,
        real_bytes,
        ticket_partition,
    } = status;
    if !decision.sample_count.is_multiple_of(10) {
        return;
    }
    let now = Instant::now();
    let current = StatusCounterSnapshot::capture(metrics, udp_tx_bytes, real_bytes, now);
    let delta = current.saturating_delta(*previous);
    let elapsed = now.saturating_duration_since(previous.at);
    let tx = delta.tx_bytes.breakdown();
    let repair_tx_bytes = tx
        .repair_request_bytes
        .saturating_add(tx.repair_response_bytes);
    let tun_ingress_bytes_per_second = rate_per_second(delta.tun_ingress_bytes, elapsed);
    let actual_cover_overhead_per_mille = ratio_per_thousand(delta.cover_bytes, delta.real_bytes);
    let actual_fec_wire_overhead_per_mille =
        ratio_per_thousand(delta.fec_bytes, delta.data_cell_bytes);
    let bulk_service_share_ppm = ratio_per_million(
        delta.bulk_service_bytes,
        delta
            .bulk_service_bytes
            .saturating_add(delta.latency_service_bytes),
    );
    let bulk_fairness_ppm = jain_fairness_ppm(&delta.bulk_flow_service);
    let latency_queue_sojourn_p95_micros = histogram_percentile_micros(&delta.latency_sojourn, 95);
    let average_record_bytes = delta
        .tun_ingress_bytes
        .checked_div(delta.tun_ingress_records)
        .unwrap_or_default();
    info!(
        %peer,
        reason = ?decision.reason,
        path_epoch = decision.path_epoch,
        samples = decision.sample_count,
        rtt_micros = telemetry.rtt.as_micros(),
        minimum_rtt_micros = telemetry.min_rtt.as_micros(),
        loss_ppm = telemetry.loss_ppm,
        tx_bytes_per_second = telemetry.delivery_rate_bytes_per_second,
        rx_bytes_per_second = telemetry.receive_rate_bytes_per_second,
        tun_ingress_bytes_per_second,
        average_record_bytes,
        train_queue_bytes = telemetry.packet_train_queue_bytes,
        latency_queue_bytes = telemetry.latency_queue_bytes,
        latency_queue_sojourn_p95_micros,
        bulk_service_share_ppm,
        bulk_fairness_ppm,
        cpu_utilization_per_mille = telemetry.cpu_utilization_per_mille,
        train_target_bytes = decision.train_target_bytes,
        bulk_quantum_cells = decision.bulk_quantum_cells,
        fec = ?decision.fec,
        receive_buffer_bytes = decision.receive_buffer_bytes,
        reassembly_budget_bytes = decision.reassembly_budget_bytes,
        receive_batch = decision.receive_batch,
        cover_profile = ?decision.cover_profile,
        cover_padding_bytes_per_second = decision.cover_padding_bytes_per_second,
        actual_cover_overhead_per_mille,
        actual_fec_wire_overhead_per_mille,
        interval_quic_udp_payload_tx_bytes = tx.quic_udp_payload_bytes,
        interval_real_record_tx_bytes = tx.real_record_bytes,
        interval_repair_tx_bytes = repair_tx_bytes,
        interval_quic_transport_residual_tx_bytes = tx.quic_transport_residual_bytes,
        protocol_datagram_errors = metrics.protocol_datagram_errors.load(Ordering::Relaxed),
        route_gate_drops = metrics.route_gate_drops.load(Ordering::Relaxed),
        tls_ticket_partition = %ticket_partition,
        remote_feedback_sequence = telemetry.repair_completed_requests,
        "V2 automatic tuning status"
    );
    *previous = current;
}
