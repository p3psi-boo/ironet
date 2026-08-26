//! Controller-finalization and policy-projection regressions.

use super::*;

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
