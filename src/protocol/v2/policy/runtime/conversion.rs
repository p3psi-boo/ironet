//! The explicit host-record <-> WIT-record conversion boundary.

use super::*;

pub(super) fn policy_fault_from_wit(fault: wit::PolicyFault) -> PolicyFaultV1 {
    match fault {
        wit::PolicyFault::Trap => PolicyFaultV1::Trap,
        wit::PolicyFault::Timeout => PolicyFaultV1::Timeout,
        wit::PolicyFault::FuelExhausted => PolicyFaultV1::FuelExhausted,
        wit::PolicyFault::OutOfMemory => PolicyFaultV1::OutOfMemory,
        wit::PolicyFault::InputTooLarge => PolicyFaultV1::InputTooLarge,
        wit::PolicyFault::OutputTooLarge => PolicyFaultV1::OutputTooLarge,
        wit::PolicyFault::InvalidOutput => PolicyFaultV1::InvalidOutput,
        wit::PolicyFault::StateTooLarge => PolicyFaultV1::StateTooLarge,
        wit::PolicyFault::AbiMismatch => PolicyFaultV1::AbiMismatch,
        wit::PolicyFault::Unavailable => PolicyFaultV1::Unavailable,
        wit::PolicyFault::Internal => PolicyFaultV1::Internal,
    }
}

fn path_reliability(value: PathReliabilityV1) -> wit::PathReliability {
    match value {
        PathReliabilityV1::Datagram => wit::PathReliability::Datagram,
        PathReliabilityV1::ReliableRelay => wit::PathReliability::ReliableRelay,
    }
}

fn objective(value: super::super::api::ObjectiveV1) -> wit::Objective {
    match value {
        super::super::api::ObjectiveV1::Balanced => wit::Objective::Balanced,
        super::super::api::ObjectiveV1::Throughput => wit::Objective::Throughput,
        super::super::api::ObjectiveV1::Latency => wit::Objective::Latency,
    }
}

fn bbr_preset(value: Bbr3PresetV1) -> wit::Bbr3Preset {
    match value {
        Bbr3PresetV1::SharedConservative => wit::Bbr3Preset::SharedConservative,
        Bbr3PresetV1::PrivateAggressive => wit::Bbr3Preset::PrivateAggressive,
        Bbr3PresetV1::LossyRadio => wit::Bbr3Preset::LossyRadio,
        Bbr3PresetV1::Policer => wit::Bbr3Preset::Policer,
        Bbr3PresetV1::LongFat => wit::Bbr3Preset::LongFat,
        Bbr3PresetV1::RelayReliable => wit::Bbr3Preset::RelayReliable,
        Bbr3PresetV1::LowRttHost => wit::Bbr3Preset::LowRttHost,
    }
}

fn bbr_preset_from_wit(value: wit::Bbr3Preset) -> Bbr3PresetV1 {
    match value {
        wit::Bbr3Preset::SharedConservative => Bbr3PresetV1::SharedConservative,
        wit::Bbr3Preset::PrivateAggressive => Bbr3PresetV1::PrivateAggressive,
        wit::Bbr3Preset::LossyRadio => Bbr3PresetV1::LossyRadio,
        wit::Bbr3Preset::Policer => Bbr3PresetV1::Policer,
        wit::Bbr3Preset::LongFat => Bbr3PresetV1::LongFat,
        wit::Bbr3Preset::RelayReliable => Bbr3PresetV1::RelayReliable,
        wit::Bbr3Preset::LowRttHost => Bbr3PresetV1::LowRttHost,
    }
}

fn cover_profile(value: CoverProfileV1) -> wit::CoverProfile {
    match value {
        CoverProfileV1::Idle => wit::CoverProfile::Idle,
        CoverProfileV1::LiveBroadcast => wit::CoverProfile::LiveBroadcast,
        CoverProfileV1::InteractiveVideo => wit::CoverProfile::InteractiveVideo,
        CoverProfileV1::GenericH3Bulk => wit::CoverProfile::GenericH3Bulk,
    }
}

fn cover_profile_from_wit(value: wit::CoverProfile) -> CoverProfileV1 {
    match value {
        wit::CoverProfile::Idle => CoverProfileV1::Idle,
        wit::CoverProfile::LiveBroadcast => CoverProfileV1::LiveBroadcast,
        wit::CoverProfile::InteractiveVideo => CoverProfileV1::InteractiveVideo,
        wit::CoverProfile::GenericH3Bulk => CoverProfileV1::GenericH3Bulk,
    }
}

fn fec_family(value: FecPresetFamilyV1) -> wit::FecPresetFamily {
    match value {
        FecPresetFamilyV1::Unspecified => wit::FecPresetFamily::Unspecified,
        FecPresetFamilyV1::Sparse => wit::FecPresetFamily::Sparse,
        FecPresetFamilyV1::Balanced => wit::FecPresetFamily::Balanced,
        FecPresetFamilyV1::Dense => wit::FecPresetFamily::Dense,
    }
}

fn fec_family_from_wit(value: wit::FecPresetFamily) -> FecPresetFamilyV1 {
    match value {
        wit::FecPresetFamily::Unspecified => FecPresetFamilyV1::Unspecified,
        wit::FecPresetFamily::Sparse => FecPresetFamilyV1::Sparse,
        wit::FecPresetFamily::Balanced => FecPresetFamilyV1::Balanced,
        wit::FecPresetFamily::Dense => FecPresetFamilyV1::Dense,
    }
}

fn wait_policy(value: RepairWaitPolicyV1) -> wit::RepairWaitPolicy {
    match value {
        RepairWaitPolicyV1::HostDefault => wit::RepairWaitPolicy::HostDefault,
        RepairWaitPolicyV1::Eager => wit::RepairWaitPolicy::Eager,
        RepairWaitPolicyV1::AfterFecWindow => wit::RepairWaitPolicy::AfterFecWindow,
        RepairWaitPolicyV1::Patient => wit::RepairWaitPolicy::Patient,
    }
}

fn wait_policy_from_wit(value: wit::RepairWaitPolicy) -> RepairWaitPolicyV1 {
    match value {
        wit::RepairWaitPolicy::HostDefault => RepairWaitPolicyV1::HostDefault,
        wit::RepairWaitPolicy::Eager => RepairWaitPolicyV1::Eager,
        wit::RepairWaitPolicy::AfterFecWindow => RepairWaitPolicyV1::AfterFecWindow,
        wit::RepairWaitPolicy::Patient => RepairWaitPolicyV1::Patient,
    }
}

fn responsibility(value: ProtectionResponsibilityV1) -> wit::ProtectionResponsibility {
    match value {
        ProtectionResponsibilityV1::HostDefault => wit::ProtectionResponsibility::HostDefault,
        ProtectionResponsibilityV1::PreferFec => wit::ProtectionResponsibility::PreferFec,
        ProtectionResponsibilityV1::PreferRepair => wit::ProtectionResponsibility::PreferRepair,
        ProtectionResponsibilityV1::Both => wit::ProtectionResponsibility::Both,
    }
}

fn responsibility_from_wit(value: wit::ProtectionResponsibility) -> ProtectionResponsibilityV1 {
    match value {
        wit::ProtectionResponsibility::HostDefault => ProtectionResponsibilityV1::HostDefault,
        wit::ProtectionResponsibility::PreferFec => ProtectionResponsibilityV1::PreferFec,
        wit::ProtectionResponsibility::PreferRepair => ProtectionResponsibilityV1::PreferRepair,
        wit::ProtectionResponsibility::Both => ProtectionResponsibilityV1::Both,
    }
}

fn scheduler_hint(value: SchedulerPresetHintV1) -> wit::SchedulerPresetHint {
    match value {
        SchedulerPresetHintV1::HostDefault => wit::SchedulerPresetHint::HostDefault,
        SchedulerPresetHintV1::LatencyFirst => wit::SchedulerPresetHint::LatencyFirst,
        SchedulerPresetHintV1::Balanced => wit::SchedulerPresetHint::Balanced,
        SchedulerPresetHintV1::BulkThroughput => wit::SchedulerPresetHint::BulkThroughput,
    }
}

fn scheduler_hint_from_wit(value: wit::SchedulerPresetHint) -> SchedulerPresetHintV1 {
    match value {
        wit::SchedulerPresetHint::HostDefault => SchedulerPresetHintV1::HostDefault,
        wit::SchedulerPresetHint::LatencyFirst => SchedulerPresetHintV1::LatencyFirst,
        wit::SchedulerPresetHint::Balanced => SchedulerPresetHintV1::Balanced,
        wit::SchedulerPresetHint::BulkThroughput => SchedulerPresetHintV1::BulkThroughput,
    }
}

fn decision_kind_from_wit(value: wit::PolicyDecisionKind) -> PolicyDecisionKindV1 {
    match value {
        wit::PolicyDecisionKind::Hold => PolicyDecisionKindV1::Hold,
        wit::PolicyDecisionKind::Exploit => PolicyDecisionKindV1::Exploit,
        wit::PolicyDecisionKind::Explore => PolicyDecisionKindV1::Explore,
        wit::PolicyDecisionKind::Rollback => PolicyDecisionKindV1::Rollback,
        wit::PolicyDecisionKind::ColdStart => PolicyDecisionKindV1::ColdStart,
        wit::PolicyDecisionKind::Fallback => PolicyDecisionKindV1::Fallback,
    }
}

fn wit_extension(value: &PolicyExtensionV1) -> wit::PolicyExtension {
    wit::PolicyExtension {
        tag: value.tag,
        payload: value.payload.clone(),
    }
}

fn wit_telemetry(value: &PolicyTelemetryV1) -> wit::PolicyTelemetry {
    wit::PolicyTelemetry {
        path_rtt_micros: value.path_rtt_micros,
        path_min_rtt_micros: value.path_min_rtt_micros,
        path_queue_delay_micros: value.path_queue_delay_micros,
        local_tx_wire_rate_bytes_per_second: value.local_tx_wire_rate_bytes_per_second,
        local_tx_tun_ingress_bytes_per_second: value.local_tx_tun_ingress_bytes_per_second,
        local_tx_real_traffic_bytes_per_second: value.local_tx_real_traffic_bytes_per_second,
        local_tx_train_build_bytes_per_second: value.local_tx_train_build_bytes_per_second,
        local_tx_packets_per_second: value.local_tx_packets_per_second,
        local_tx_loss_ppm: value.local_tx_loss_ppm,
        local_tx_burst_loss_cells: value.local_tx_burst_loss_cells,
        local_tx_average_record_bytes: value.local_tx_average_record_bytes,
        local_tx_gso_ingress_ratio_ppm: value.local_tx_gso_ingress_ratio_ppm,
        local_tx_packet_train_queue_bytes: value.local_tx_packet_train_queue_bytes,
        local_tx_latency_queue_bytes: value.local_tx_latency_queue_bytes,
        local_tx_bulk_preemption_delay_average_micros: value
            .local_tx_bulk_preemption_delay_average_micros,
        local_tx_controller_pacing_rate_bytes_per_second: value
            .local_tx_controller_pacing_rate_bytes_per_second,
        local_tx_controller_send_quantum_bytes: value.local_tx_controller_send_quantum_bytes,
        local_tx_controller_state: value.local_tx_controller_state,
        local_tx_controller_bw_bytes_per_second: value.local_tx_controller_bw_bytes_per_second,
        local_tx_controller_inflight_longterm_bytes: value
            .local_tx_controller_inflight_longterm_bytes,
        local_tx_controller_guard_transitions_delta: value
            .local_tx_controller_guard_transitions_delta,
        local_tx_controller_app_limited: value.local_tx_controller_app_limited,
        local_tx_controller_tunables_generation: value.local_tx_controller_tunables_generation,
        local_tx_controller_params_generation: value.local_tx_controller_params_generation,
        local_tx_controller_clamped_writes: value.local_tx_controller_clamped_writes,
        local_rx_wire_rate_bytes_per_second: value.local_rx_wire_rate_bytes_per_second,
        local_rx_reassembly_pressure_evictions: value.local_rx_reassembly_pressure_evictions,
        remote_goodput_bytes_per_second: value.remote_goodput_bytes_per_second,
        remote_residual_loss_ppm: value.remote_residual_loss_ppm,
        remote_reorder_ppm: value.remote_reorder_ppm,
        remote_expired_stripes_delta: value.remote_expired_stripes_delta,
        remote_wasted_parity_per_mille: value.remote_wasted_parity_per_mille,
        remote_fec_recovery_per_mille: value.remote_fec_recovery_per_mille,
        remote_repair_hit_per_mille: value.remote_repair_hit_per_mille,
        remote_repair_completed_requests: value.remote_repair_completed_requests,
        remote_repair_response_latency_micros: value.remote_repair_response_latency_micros,
        latency_sojourn_p50_micros: value.latency_sojourn_p50_micros,
        latency_sojourn_p95_micros: value.latency_sojourn_p95_micros,
        latency_sojourn_p99_micros: value.latency_sojourn_p99_micros,
        latency_queue_recently_nonempty: value.latency_queue_recently_nonempty,
        host_cpu_utilization_per_mille: value.host_cpu_utilization_per_mille,
    }
}

fn wit_utility(value: &HostUtilityV1) -> wit::HostUtility {
    wit::HostUtility {
        objective: objective(value.objective),
        valid: value.valid,
        utility_milli: value.utility_milli,
        throughput_milli: value.throughput_milli,
        queue_delay_milli: value.queue_delay_milli,
        latency_sojourn_milli: value.latency_sojourn_milli,
        residual_loss_milli: value.residual_loss_milli,
        jitter_milli: value.jitter_milli,
        cpu_milli: value.cpu_milli,
        wire_overhead_milli: value.wire_overhead_milli,
        memory_milli: value.memory_milli,
        goodput_bytes_per_second: value.goodput_bytes_per_second,
    }
}

fn wit_limits(value: &HostLimitsV1) -> wit::HostLimits {
    wit::HostLimits {
        train_target_floor_bytes: value.train_target_floor_bytes,
        train_target_cap_bytes: value.train_target_cap_bytes,
        bulk_quantum_floor_cells: value.bulk_quantum_floor_cells,
        bulk_quantum_cap_cells: value.bulk_quantum_cap_cells,
        send_buffer_floor_bytes: value.send_buffer_floor_bytes,
        send_buffer_cap_bytes: value.send_buffer_cap_bytes,
        receive_buffer_floor_bytes: value.receive_buffer_floor_bytes,
        receive_buffer_cap_bytes: value.receive_buffer_cap_bytes,
        receive_batch_cap: value.receive_batch_cap,
        repair_cache_cap_bytes: value.repair_cache_cap_bytes,
        fec_data_cells_cap: value.fec_data_cells_cap,
        fec_parity_cells_cap: value.fec_parity_cells_cap,
        fec_parity_per_mille_cap: value.fec_parity_per_mille_cap,
        cover_overhead_cap_per_mille: value.cover_overhead_cap_per_mille,
        cover_padding_cap_bytes_per_second: value.cover_padding_cap_bytes_per_second,
        pacing_cap_bytes_per_second: value.pacing_cap_bytes_per_second,
        egress_priority_cap: value.egress_priority_cap,
        state_cap_bytes: value.state_cap_bytes,
        extension_payload_cap_bytes: value.extension_payload_cap_bytes,
        extension_count_cap: value.extension_count_cap,
    }
}

fn wit_capabilities(value: &HostCapabilitiesV1) -> wit::HostCapabilities {
    wit::HostCapabilities {
        abi_major: value.abi_major,
        abi_minor: value.abi_minor,
        fec_supported: value.fec_supported,
        repair_supported: value.repair_supported,
        cover_supported: value.cover_supported,
        bbr_tunables_writable: value.bbr_tunables_writable,
        egress_coordinator: value.egress_coordinator,
        shadow: value.shadow,
        extension_tags: value.extension_tags.clone(),
    }
}

fn wit_egress_view(value: &EgressAllocationViewV1) -> wit::EgressAllocationView {
    wit::EgressAllocationView {
        assigned_rate_bytes_per_second: value.assigned_rate_bytes_per_second,
        node_cap_bytes_per_second: value.node_cap_bytes_per_second,
        node_demand_bytes_per_second: value.node_demand_bytes_per_second,
        pressure_per_mille: value.pressure_per_mille,
        active_peers: value.active_peers,
        allocation_generation: value.allocation_generation,
    }
}

fn wit_bbr_effective(value: &BbrEffectiveV1) -> wit::BbrEffective {
    wit::BbrEffective {
        preset: bbr_preset(value.preset),
        probe_bw_up_pacing_gain_milli: value.probe_bw_up_pacing_gain_milli,
        probe_bw_down_pacing_gain_milli: value.probe_bw_down_pacing_gain_milli,
        cruise_pacing_gain_milli: value.cruise_pacing_gain_milli,
        default_cwnd_gain_milli: value.default_cwnd_gain_milli,
        probe_bw_up_cwnd_gain_milli: value.probe_bw_up_cwnd_gain_milli,
        headroom_milli: value.headroom_milli,
        beta_milli: value.beta_milli,
        loss_threshold_milli: value.loss_threshold_milli,
        loss_is_congestion: value.loss_is_congestion,
        queue_guard_inflation_milli: value.queue_guard_inflation_milli,
        queue_guard_slack_micros: value.queue_guard_slack_micros,
        probe_rtt_interval_millis: value.probe_rtt_interval_millis,
        probe_rtt_duration_millis: value.probe_rtt_duration_millis,
        probe_rtt_cwnd_gain_milli: value.probe_rtt_cwnd_gain_milli,
        min_probe_wait_millis: value.min_probe_wait_millis,
        max_added_probe_wait_millis: value.max_added_probe_wait_millis,
        pacing_cap_bytes_per_second: value.pacing_cap_bytes_per_second,
        cwnd_floor_bytes: value.cwnd_floor_bytes,
        cwnd_cap_bytes: value.cwnd_cap_bytes,
        startup_bw_hint_bytes_per_second: value.startup_bw_hint_bytes_per_second,
    }
}

fn wit_scheduler_effective(value: &SchedulerEffectiveV1) -> wit::SchedulerEffective {
    wit::SchedulerEffective {
        train_target_bytes: value.train_target_bytes,
        bulk_quantum_cells: value.bulk_quantum_cells,
        bulk_admission_window_bytes: value.bulk_admission_window_bytes,
        preset_hint: scheduler_hint(value.preset_hint),
    }
}

fn wit_fec_effective(value: &FecEffectiveV1) -> wit::FecEffective {
    wit::FecEffective {
        enabled: value.enabled,
        data_cells: value.data_cells,
        parity_cells: value.parity_cells,
        preset_family: fec_family(value.preset_family),
    }
}

fn wit_repair_effective(value: &RepairEffectiveV1) -> wit::RepairEffective {
    wit::RepairEffective {
        cache_bytes: value.cache_bytes,
        retention_target_millis: value.retention_target_millis,
        wait_policy: wait_policy(value.wait_policy),
        responsibility: responsibility(value.responsibility),
    }
}

fn wit_tx_effective(value: &TxEffectiveV1) -> wit::TxEffective {
    wit::TxEffective {
        send_buffer_bytes: value.send_buffer_bytes,
        datagram_admission_bytes: value.datagram_admission_bytes,
        producer_window_bytes: value.producer_window_bytes,
    }
}

fn wit_rx_effective(value: &RxEffectiveV1) -> wit::RxEffective {
    wit::RxEffective {
        receive_buffer_bytes: value.receive_buffer_bytes,
        receive_batch: value.receive_batch,
        reassembly_budget_bytes: value.reassembly_budget_bytes,
        active_train_budget: value.active_train_budget,
    }
}

fn wit_cover_effective(value: &CoverEffectiveV1) -> wit::CoverEffective {
    wit::CoverEffective {
        profile: cover_profile(value.profile),
        overhead_per_mille: value.overhead_per_mille,
        padding_bytes_per_second: value.padding_bytes_per_second,
    }
}

fn wit_egress_request(value: &EgressRequestV1) -> wit::EgressRequest {
    wit::EgressRequest {
        desired_rate_bytes_per_second: value.desired_rate_bytes_per_second,
        minimum_rate_bytes_per_second: value.minimum_rate_bytes_per_second,
        priority: value.priority,
        exploring: value.exploring,
    }
}

fn wit_effective(value: &EffectiveActionViewV1) -> wit::EffectiveAction {
    wit::EffectiveAction {
        reason: match value.reason {
            super::super::api::ActionReasonV1::ColdStart => wit::ActionReason::ColdStart,
            super::super::api::ActionReasonV1::TelemetryUnavailable => {
                wit::ActionReason::TelemetryUnavailable
            }
            super::super::api::ActionReasonV1::PathChanged => wit::ActionReason::PathChanged,
            super::super::api::ActionReasonV1::HealthyLowLoss => wit::ActionReason::HealthyLowLoss,
            super::super::api::ActionReasonV1::RandomLoss => wit::ActionReason::RandomLoss,
            super::super::api::ActionReasonV1::BurstLoss => wit::ActionReason::BurstLoss,
            super::super::api::ActionReasonV1::Congested => wit::ActionReason::Congested,
            super::super::api::ActionReasonV1::CpuLimited => wit::ActionReason::CpuLimited,
            super::super::api::ActionReasonV1::ReliablePath => wit::ActionReason::ReliablePath,
        },
        path_epoch: value.path_epoch,
        sample_count: value.sample_count,
        bbr: wit_bbr_effective(&value.bbr),
        scheduler: wit_scheduler_effective(&value.scheduler),
        fec: wit_fec_effective(&value.fec),
        repair: wit_repair_effective(&value.repair),
        tx: wit_tx_effective(&value.tx),
        rx: wit_rx_effective(&value.rx),
        cover: wit_cover_effective(&value.cover),
        egress: wit_egress_request(&value.egress),
    }
}

pub(super) fn wit_input(value: &PolicyInputV1) -> wit::PolicyInput {
    wit::PolicyInput {
        logical_tick: value.logical_tick,
        deterministic_seed: value.deterministic_seed,
        peer_hash: value.peer_hash.to_vec(),
        path_epoch: value.path_epoch,
        reliability: path_reliability(value.reliability),
        telemetry: wit_telemetry(&value.telemetry),
        previous: wit_effective(&value.previous),
        previous_utility: wit_utility(&value.previous_utility),
        limits: wit_limits(&value.limits),
        capabilities: wit_capabilities(&value.capabilities),
        egress: wit_egress_view(&value.egress),
        extensions: value.extensions.iter().map(wit_extension).collect(),
        state: value.state.clone(),
    }
}

fn label_from_wit(value: wit::PolicyLabel) -> Result<PolicyLabelV1> {
    ensure!(
        value.len() <= ironet_policy_abi::POLICY_LABEL_BYTES,
        "diagnostic label is too long"
    );
    std::str::from_utf8(&value).context("diagnostic label is not UTF-8")?;
    let mut label = [0u8; ironet_policy_abi::POLICY_LABEL_BYTES];
    label[..value.len()].copy_from_slice(&value);
    Ok(PolicyLabelV1(label))
}

pub(super) fn output_from_wit(
    value: wit::PolicyOutput,
    _input: &PolicyInputV1,
) -> Result<PolicyOutputV1> {
    let diagnostics = value.diagnostics;
    Ok(PolicyOutputV1 {
        candidate: candidate_from_wit(value.candidate),
        next_state: value.next_state,
        diagnostics: PolicyDiagnosticsV1 {
            decision_kind: decision_kind_from_wit(diagnostics.decision_kind),
            context_label: label_from_wit(diagnostics.context_label)?,
            applied_arm_label: label_from_wit(diagnostics.applied_arm_label)?,
            baseline_arm_label: label_from_wit(diagnostics.baseline_arm_label)?,
            predicted_advantage_milli: diagnostics.predicted_advantage_milli,
            confidence_per_mille: diagnostics.confidence_per_mille,
            exploring: diagnostics.exploring,
            rollback: diagnostics.rollback,
            rollbacks: diagnostics.rollbacks,
            guest_utility_milli: diagnostics.guest_utility_milli,
            state_schema: diagnostics.state_schema,
        },
    })
}

fn candidate_from_wit(value: wit::CandidateAction) -> CandidateActionV1 {
    CandidateActionV1 {
        bbr: value.bbr.map(bbr_candidate_from_wit),
        scheduler: value.scheduler.map(scheduler_candidate_from_wit),
        fec: value.fec.map(fec_candidate_from_wit),
        repair: value.repair.map(repair_candidate_from_wit),
        tx: value.tx.map(tx_candidate_from_wit),
        rx: value.rx.map(rx_candidate_from_wit),
        cover: value.cover.map(cover_candidate_from_wit),
        egress_request: value.egress_request.map(egress_request_from_wit),
        extensions: value
            .extensions
            .into_iter()
            .map(extension_from_wit)
            .collect(),
    }
}

fn extension_from_wit(value: wit::PolicyExtension) -> PolicyExtensionV1 {
    PolicyExtensionV1 {
        tag: value.tag,
        payload: value.payload,
    }
}

fn bbr_candidate_from_wit(value: wit::BbrCandidate) -> BbrCandidateV1 {
    BbrCandidateV1 {
        preset: value.preset.map(bbr_preset_from_wit),
        probe_bw_up_pacing_gain_milli: value.probe_bw_up_pacing_gain_milli,
        probe_bw_down_pacing_gain_milli: value.probe_bw_down_pacing_gain_milli,
        cruise_pacing_gain_milli: value.cruise_pacing_gain_milli,
        default_cwnd_gain_milli: value.default_cwnd_gain_milli,
        probe_bw_up_cwnd_gain_milli: value.probe_bw_up_cwnd_gain_milli,
        headroom_milli: value.headroom_milli,
        beta_milli: value.beta_milli,
        loss_threshold_milli: value.loss_threshold_milli,
        loss_is_congestion: value.loss_is_congestion,
        queue_guard_inflation_milli: value.queue_guard_inflation_milli,
        queue_guard_slack_micros: value.queue_guard_slack_micros,
        probe_rtt_interval_millis: value.probe_rtt_interval_millis,
        probe_rtt_duration_millis: value.probe_rtt_duration_millis,
        probe_rtt_cwnd_gain_milli: value.probe_rtt_cwnd_gain_milli,
        min_probe_wait_millis: value.min_probe_wait_millis,
        max_added_probe_wait_millis: value.max_added_probe_wait_millis,
        pacing_cap_bytes_per_second: value.pacing_cap_bytes_per_second,
        cwnd_floor_bytes: value.cwnd_floor_bytes,
        cwnd_cap_bytes: value.cwnd_cap_bytes,
        startup_bw_hint_bytes_per_second: value.startup_bw_hint_bytes_per_second,
    }
}

fn scheduler_candidate_from_wit(value: wit::SchedulerCandidate) -> SchedulerCandidateV1 {
    SchedulerCandidateV1 {
        train_target_bytes: value.train_target_bytes,
        bulk_quantum_cells: value.bulk_quantum_cells,
        bulk_admission_window_bytes: value.bulk_admission_window_bytes,
        preset_hint: value.preset_hint.map(scheduler_hint_from_wit),
    }
}

fn fec_candidate_from_wit(value: wit::FecCandidate) -> FecCandidateV1 {
    FecCandidateV1 {
        enabled: value.enabled,
        data_cells: value.data_cells,
        parity_cells: value.parity_cells,
        preset_family: value.preset_family.map(fec_family_from_wit),
    }
}

fn repair_candidate_from_wit(value: wit::RepairCandidate) -> RepairCandidateV1 {
    RepairCandidateV1 {
        cache_bytes: value.cache_bytes,
        retention_target_millis: value.retention_target_millis,
        wait_policy: value.wait_policy.map(wait_policy_from_wit),
        responsibility: value.responsibility.map(responsibility_from_wit),
    }
}

fn tx_candidate_from_wit(value: wit::TxCandidate) -> TxCandidateV1 {
    TxCandidateV1 {
        send_buffer_bytes: value.send_buffer_bytes,
        datagram_admission_bytes: value.datagram_admission_bytes,
        producer_window_bytes: value.producer_window_bytes,
    }
}

fn rx_candidate_from_wit(value: wit::RxCandidate) -> RxCandidateV1 {
    RxCandidateV1 {
        receive_buffer_bytes: value.receive_buffer_bytes,
        receive_batch: value.receive_batch,
        reassembly_budget_bytes: value.reassembly_budget_bytes,
        active_train_budget: value.active_train_budget,
    }
}

fn cover_candidate_from_wit(value: wit::CoverCandidate) -> CoverCandidateV1 {
    CoverCandidateV1 {
        profile: value.profile.map(cover_profile_from_wit),
        overhead_per_mille: value.overhead_per_mille,
        padding_bytes_per_second: value.padding_bytes_per_second,
    }
}

fn egress_request_from_wit(value: wit::EgressRequest) -> EgressRequestV1 {
    EgressRequestV1 {
        desired_rate_bytes_per_second: value.desired_rate_bytes_per_second,
        minimum_rate_bytes_per_second: value.minimum_rate_bytes_per_second,
        priority: value.priority,
        exploring: value.exploring,
    }
}
