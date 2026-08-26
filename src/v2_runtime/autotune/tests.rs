//! Regression tests for autotune helpers and policy lifecycle.

use std::sync::atomic::Ordering;

use iroh::SecretKey;

use super::super::V2RuntimeConfig;
use super::*;
use crate::{
    derp::DerpPublicKey,
    protocol::v2::{policy::api::BbrHostExt, tuning::Bbr3ProposalV2},
};

fn product_config() -> crate::config::Config {
    toml::from_str(include_str!("../../../config/example.toml")).unwrap()
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
fn remote_feedback_rates_expire_as_one_window() {
    let metrics = RuntimeMetrics::default();
    let started = Instant::now();
    let mut window = RemoteFeedbackWindowV2::capture(&metrics, started);
    metrics.remote_fec_parity_rx.store(10, Ordering::Relaxed);
    metrics
        .remote_fec_recovered_cells
        .store(5, Ordering::Relaxed);
    metrics
        .remote_delivered_payload_bytes
        .store(8_000, Ordering::Relaxed);
    metrics.data_cell_tx_datagrams.store(100, Ordering::Relaxed);
    metrics.remote_missing_cells.store(1, Ordering::Relaxed);
    metrics.remote_loss_run_1.store(1, Ordering::Relaxed);
    metrics
        .remote_repair_completed_requests
        .store(7, Ordering::Relaxed);
    metrics.remote_feedback_sequence.store(1, Ordering::Release);

    let fresh = window.sample(&metrics, started + Duration::from_secs(1));
    assert_eq!(fresh.sequence, 1);
    assert_eq!(fresh.fec_recovery_per_mille, 500);
    assert_eq!(fresh.receiver_goodput_bytes_per_second, 8_000);
    assert!(fresh.residual_loss_ppm > 0);
    assert_eq!(fresh.repair_completed_requests, 7);

    let stale = window.sample(
        &metrics,
        started + Duration::from_secs(1) + REMOTE_FEEDBACK_TTL,
    );
    assert_eq!(stale.sequence, 1);
    assert_eq!(stale.fec_recovery_per_mille, 0);
    assert_eq!(stale.receiver_goodput_bytes_per_second, 0);
    assert_eq!(stale.residual_loss_ppm, 0);
    assert_eq!(stale.repair_completed_requests, 7);
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

fn observe_bulk_admission(state: &mut CapacityProbeStateV2, bytes: u64) {
    let next = state.bulk_admission_counter.saturating_add(bytes);
    state.update_bulk_admission_counter(next);
}

#[path = "tests/capacity_probe.rs"]
mod capacity_probe;
#[path = "tests/controller.rs"]
mod controller;
