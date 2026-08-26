//! Capacity-probe regression matrix.

use super::*;

#[test]
fn finalized_bbr_effective_is_tunable_authority_and_idempotent() {
    let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
    let mut effective = BbrEffectiveV1::from_proposal(&proposal);
    let adaptive_floor =
        finalize_bbr3_effective(queued_adaptive_floor_telemetry(), 96 * 1024, &mut effective);

    assert_eq!(adaptive_floor, 208 * 1024);
    assert_eq!(effective.cwnd_floor_bytes, adaptive_floor);

    let tunables = Bbr3Tunables::default();
    assert!(apply_bbr3_effective(&tunables, &effective));
    assert_eq!(
        tunables_snapshot(&tunables),
        effective_tunables_snapshot(&effective)
    );
    assert_eq!(tunables.generation.load(Ordering::Acquire), 1);
    assert!(!apply_bbr3_effective(&tunables, &effective));
    assert_eq!(tunables.generation.load(Ordering::Acquire), 1);
}

#[test]
fn bursty_single_empty_tick_does_not_repeat_capacity_probe() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 1;
    observe_bulk_admission(&mut state, 1);

    assert!(!state.update(telemetry, false));
    assert!(!state.update(telemetry, false));

    telemetry.tun_ingress_bytes_per_second = 0;
    telemetry.packet_train_queue_bytes = 0;
    assert!(!state.update(telemetry, false));
    assert!(state.bulk_active);
    assert_eq!(state.bulk_idle_ticks, 1);

    // One empty producer sample between bursts remains the same active
    // epoch, so it cannot ask BBR to reprobe a second time.
    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
    observe_bulk_admission(&mut state, 1);
    assert!(!state.update(telemetry, false));
    assert_eq!(state.bulk_idle_ticks, 0);

    telemetry.tun_ingress_bytes_per_second = 0;
    telemetry.packet_train_queue_bytes = 0;
    assert!(!state.update(telemetry, false));
    assert!(state.bulk_active);
    assert!(!state.update(telemetry, false));
    assert!(!state.bulk_active);

    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
    observe_bulk_admission(&mut state, 1);
    assert!(state.update(telemetry, false));
}

#[test]
fn bulk_service_counter_edge_fires_once_and_rearms_after_idle() {
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 0;
    telemetry.packet_train_queue_bytes = 0;
    let mut state = CapacityProbeStateV2::default();
    let tunables = Bbr3Tunables::default();
    state.initialize_bulk_service_counter(telemetry.path_epoch, 100);

    // Control/latency traffic and repeated polls do not change the Bulk
    // counter, so neither can request capacity discovery.
    assert!(!state.update_bulk_service_counter(100));
    assert!(!state.update_bulk_service_counter(100));

    if state.update_bulk_service_counter(101) {
        publish_capacity_probe(&tunables);
    }
    assert_eq!(
        tunables.capacity_probe_generation.load(Ordering::Acquire),
        0
    );
    assert!(state.bulk_active);
    // Further bytes in the same active epoch are coalesced.
    assert!(!state.update_bulk_service_counter(102));
    assert!(!state.update_bulk_service_counter(103));

    // The first full tick consumes service observed by the fast path, so
    // it is active rather than the first idle tick.
    assert!(!state.update(telemetry, false));
    assert!(state.bulk_active);
    assert_eq!(state.bulk_idle_ticks, 0);
    assert!(!state.update(telemetry, false));
    assert!(state.bulk_active);
    assert_eq!(state.bulk_idle_ticks, 1);
    assert!(!state.update(telemetry, false));
    assert!(!state.bulk_active);
    assert!(state.bulk_idle_verified);

    if state.update_bulk_service_counter(104) {
        publish_capacity_probe(&tunables);
    }
    assert_eq!(
        tunables.capacity_probe_generation.load(Ordering::Acquire),
        1
    );
    assert!(!state.update_bulk_service_counter(105));
}

#[test]
fn clean_underestimated_initial_bulk_requests_one_delayed_probe() {
    let mut state = CapacityProbeStateV2::default();
    state.initialize_bulk_service_counter(1, 100);
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.controller_state = 3; // ProbeBW Cruise.
    telemetry.controller_pacing_rate_bytes_per_second = 40_000_000;
    telemetry.tun_ingress_bytes_per_second = 80_000_000;
    telemetry.loss_ppm = 0;
    telemetry.residual_loss_ppm = 0;
    telemetry.burst_loss_cells = 0;

    assert!(!state.update_bulk_service_counter(101));
    assert_eq!(
        state.initial_bulk_probe,
        InitialBulkProbeV2::AwaitingSampleBoundary
    );
    let mut partial = telemetry;
    partial.tun_ingress_bytes_per_second = 1_000_000;
    assert!(!state.update(partial, false));
    assert_eq!(
        state.initial_bulk_probe,
        InitialBulkProbeV2::AwaitingCompleteTick
    );
    assert!(state.update(telemetry, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
    // The decision is one-shot even while demand remains above pacing.
    assert!(!state.update(telemetry, false));
    assert!(!state.update_bulk_service_counter(102));
    assert!(state.bulk_active);
}

#[test]
fn home_like_partial_pressure_is_retained_until_the_clean_complete_tick() {
    let mut state = CapacityProbeStateV2::default();
    let mut partial = queued_adaptive_floor_telemetry();
    state.initialize_bulk_service_counter(partial.path_epoch, 100);
    partial.controller_state = 3; // ProbeBW Cruise.
    partial.controller_pacing_rate_bytes_per_second = 308_267;
    partial.tun_ingress_bytes_per_second = 653_600;
    partial.loss_ppm = 0;
    partial.residual_loss_ppm = 0;
    partial.burst_loss_cells = 0;

    assert!(!state.update_bulk_service_counter(101));
    assert!(!state.update(partial, false));
    assert!(state.initial_sample_incomplete);
    assert!(state.initial_clean_demand_seen);
    assert!(!state.update_loss_episode_if_complete(partial, false));

    let mut complete = partial;
    complete.controller_state = 5;
    complete.controller_pacing_rate_bytes_per_second = 507_945;
    complete.tun_ingress_bytes_per_second = 424_041;
    assert!(
        complete.tun_ingress_bytes_per_second < complete.controller_pacing_rate_bytes_per_second
    );
    assert!(state.update(complete, false));
    assert!(!state.initial_clean_demand_seen);
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);

    assert!(!state.update(complete, false));
    assert!(!state.update_loss_episode_if_complete(complete, false));
}

#[test]
fn sustained_initial_bulk_reprobes_before_a_lossy_telemetry_boundary() {
    let mut state = CapacityProbeStateV2::default();
    state.initialize_bulk_service_counter(1, 0);

    // The first two 50 ms service edges prove that a real Bulk epoch has
    // started. This direct cross-layer evidence arrives before the next
    // one-second interval, where an asymmetric upload may already show
    // random loss and otherwise consume the old delayed decision.
    assert!(!state.update_bulk_service_counter(8 * 1024));
    assert!(!state.sustained_initial_bulk_requires_probe(3, false));
    assert!(!state.update_bulk_service_counter(16 * 1024));
    assert!(state.sustained_initial_bulk_requires_probe(3, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);

    // It is a one-shot semantic epoch boundary, not a timer-driven
    // restart while the transfer continues.
    assert!(!state.update_bulk_service_counter(24 * 1024));
    assert!(!state.sustained_initial_bulk_requires_probe(3, false));
}

#[test]
fn classified_bulk_admission_reprobes_before_the_first_service_byte() {
    let mut state = CapacityProbeStateV2::default();
    state.initialize_bulk_service_counter(1, 0);
    state.initialize_bulk_admission_counter(0);

    // A loss-reduced controller can have queued Bulk work long before it
    // receives permission to send its first cell. The classifier boundary
    // preserves that demand signal without promoting latency traffic.
    state.update_bulk_admission_counter(8 * 1024);
    assert!(!state.sustained_initial_bulk_requires_probe(3, false));
    assert!(!state.update_bulk_service_counter(0));

    state.update_bulk_admission_counter(16 * 1024);
    assert!(state.sustained_initial_bulk_requires_probe(3, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
    assert!(!state.update_bulk_service_counter(0));
    assert!(!state.sustained_initial_bulk_requires_probe(3, false));
}

#[test]
fn unclassified_tun_ingress_cannot_consume_the_bulk_probe_epoch() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.controller_state = 3;
    telemetry.tun_ingress_bytes_per_second = 8 * 1024 * 1024;

    // ICMP, control, and latency TUN records share the aggregate ingress
    // counter. They must not consume the one semantic Bulk discovery
    // edge before the classifier observes the actual transfer.
    assert!(!state.update(telemetry, false));
    assert!(!state.bulk_active);
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::AwaitingEdge);

    state.initialize_bulk_admission_counter(0);
    state.update_bulk_admission_counter(8 * 1024);
    state.update_bulk_admission_counter(16 * 1024);
    assert!(state.sustained_initial_bulk_requires_probe(3, false));
}

#[test]
fn fast_initial_bulk_probe_leaves_native_startup_and_policer_episodes_owned() {
    let mut state = CapacityProbeStateV2::default();
    state.initialize_bulk_service_counter(1, 0);
    assert!(!state.update_bulk_service_counter(8 * 1024));
    assert!(!state.update_bulk_service_counter(16 * 1024));

    assert!(!state.sustained_initial_bulk_requires_probe(0, false));
    assert!(!state.sustained_initial_bulk_requires_probe(3, true));
    assert_ne!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
}

#[test]
fn p2_like_partial_without_pressure_and_lossy_complete_is_suppressed() {
    let mut state = CapacityProbeStateV2::default();
    let mut partial = queued_adaptive_floor_telemetry();
    state.initialize_bulk_service_counter(partial.path_epoch, 100);
    partial.controller_state = 3; // ProbeBW Cruise.
    partial.controller_pacing_rate_bytes_per_second = 875_843;
    partial.tun_ingress_bytes_per_second = 394_628;
    partial.loss_ppm = 0;
    partial.residual_loss_ppm = 0;
    partial.burst_loss_cells = 0;

    assert!(!state.update_bulk_service_counter(101));
    assert!(!state.update(partial, false));
    assert!(state.initial_sample_incomplete);
    assert!(!state.initial_clean_demand_seen);
    assert!(!state.update_loss_episode_if_complete(partial, false));

    let mut complete = partial;
    complete.controller_pacing_rate_bytes_per_second = 300_000;
    complete.tun_ingress_bytes_per_second = 600_000;
    complete.loss_ppm = 40_523;
    assert!(!state.update(complete, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
    assert!(!state.update_loss_episode_if_complete(complete, false));
    assert!(state.loss_episode);

    // A later clean high-pressure sample cannot resurrect the consumed
    // initial decision. The complete tick's real loss episode remains
    // independently owned by the loss-recovery state machine.
    complete.loss_ppm = 0;
    for _ in 0..3 {
        assert!(!state.update(complete, false));
    }
}

#[test]
fn lossy_partial_initial_bulk_sample_cannot_seed_a_second_recovery_probe() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
    telemetry.controller_state = 3; // ProbeBW Cruise.
    telemetry.controller_pacing_rate_bytes_per_second = 4_000_000;
    telemetry.tun_ingress_bytes_per_second = 8_000_000;
    telemetry.loss_ppm = 0;
    telemetry.residual_loss_ppm = 0;
    telemetry.burst_loss_cells = 0;

    assert!(!state.update_bulk_service_counter(101));

    let mut partial = telemetry;
    partial.loss_ppm = 20_000;
    assert!(!state.update(partial, false));
    assert!(state.initial_sample_incomplete);
    assert!(!state.update_loss_episode_if_complete(partial, false));
    assert!(!state.loss_episode);

    // The first complete clean interval makes exactly the initial-Bulk
    // decision. The discarded partial loss must not mature into a second
    // loss-recovery restart on later clean intervals.
    assert!(state.update(telemetry, false));
    assert!(!state.update_loss_episode_if_complete(telemetry, false));
    let mut requests = 1;
    for _ in 0..3 {
        requests += usize::from(state.update(telemetry, false));
        requests += usize::from(state.update_loss_episode_if_complete(telemetry, false));
    }
    assert_eq!(requests, 1);
    assert!(!state.loss_episode);
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
}

#[test]
fn startup_lossy_partial_then_probebw_clean_complete_probes_only_once() {
    let mut state = CapacityProbeStateV2::default();
    let mut partial = queued_adaptive_floor_telemetry();
    state.initialize_bulk_service_counter(partial.path_epoch, 100);
    partial.controller_state = 0; // Native Startup owns the partial tick.
    partial.controller_pacing_rate_bytes_per_second = 4_000_000;
    partial.tun_ingress_bytes_per_second = 8_000_000;
    partial.loss_ppm = 20_000;

    assert!(!state.update_bulk_service_counter(101));
    assert!(!state.update(partial, false));
    assert!(state.initial_sample_incomplete);
    assert!(!state.update_loss_episode_if_complete(partial, false));
    assert!(!state.loss_episode);

    let mut complete = partial;
    complete.controller_state = 3; // ProbeBW Cruise.
    complete.loss_ppm = 0;
    complete.residual_loss_ppm = 0;
    complete.burst_loss_cells = 0;
    assert!(state.update(complete, false));
    assert!(!state.update_loss_episode_if_complete(complete, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);

    for _ in 0..3 {
        assert!(!state.update(complete, false));
        assert!(!state.update_loss_episode_if_complete(complete, false));
    }
    assert!(!state.loss_episode);
}

#[test]
fn initial_bulk_probe_decision_is_consumed_only_once() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.controller_state = 3; // ProbeBW Cruise.
    telemetry.controller_pacing_rate_bytes_per_second = 4_000_000;
    telemetry.tun_ingress_bytes_per_second = 8_000_000;
    telemetry.loss_ppm = 0;
    telemetry.residual_loss_ppm = 0;
    telemetry.burst_loss_cells = 0;
    observe_bulk_admission(&mut state, 8 * 1024 * 1024);

    // The normal path may observe initial Bulk first, but that first
    // sample is still a partial window. Only the following complete tick
    // may make the one-shot decision.
    assert!(!state.update(telemetry, false));
    assert_eq!(
        state.initial_bulk_probe,
        InitialBulkProbeV2::AwaitingCompleteTick
    );
    assert!(state.update(telemetry, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
    assert!(!state.update(telemetry, false));
    assert!(!state.update(telemetry, false));
}

#[test]
fn lossy_initial_bulk_tick_is_suppressed_when_the_fast_edge_was_missed() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
    telemetry.controller_state = 3; // ProbeBW Cruise.
    telemetry.controller_pacing_rate_bytes_per_second = 8_000_000;
    telemetry.tun_ingress_bytes_per_second = 12_000_000;
    telemetry.loss_ppm = 20_000;

    // This exercises the telemetry-only fallback. The runtime's 50 ms
    // edge path can publish sustained service before this lossy boundary;
    // if that path was unavailable, this one-shot fallback remains
    // intentionally conservative.
    assert!(!state.update_bulk_service_counter(101));
    let mut partial = telemetry;
    partial.loss_ppm = 0;
    assert!(!state.update(partial, false));
    assert!(!state.update(telemetry, false));
    telemetry.loss_ppm = 0;
    assert!(!state.update(telemetry, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
}

#[test]
fn native_startup_permanently_suppresses_initial_bulk_probe() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
    telemetry.controller_state = 0; // Startup is already probing.
    telemetry.controller_pacing_rate_bytes_per_second = 8_000_000;
    telemetry.tun_ingress_bytes_per_second = 12_000_000;

    assert!(!state.update_bulk_service_counter(101));
    assert!(!state.update(telemetry, false));
    assert!(!state.update(telemetry, false));
    telemetry.controller_state = 3;
    assert!(!state.update(telemetry, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
}

#[test]
fn initial_bulk_probe_is_suppressed_during_controller_policer_episode() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
    telemetry.controller_state = 3;
    telemetry.controller_pacing_rate_bytes_per_second = 8_000_000;
    telemetry.tun_ingress_bytes_per_second = 12_000_000;

    assert!(!state.update_bulk_service_counter(101));
    assert!(!state.update(telemetry, false));
    assert!(!state.update(telemetry, true));
    assert!(!state.update(telemetry, false));
    assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
}

#[test]
fn fast_capacity_probe_requires_the_current_selected_path_identity() {
    assert!(!fast_capacity_probe_path_matches("", "ip:2001:db8::1"));
    assert!(fast_capacity_probe_path_matches(
        "ip:2001:db8::1",
        "ip:2001:db8::1"
    ));
    assert!(!fast_capacity_probe_path_matches(
        "ip:2001:db8::1",
        "ip:2001:db8::2"
    ));
}

#[test]
fn bulk_service_clears_a_partial_confirmed_idle_horizon() {
    let mut state = CapacityProbeStateV2::default();
    state.initialize_bulk_service_counter(1, 100);
    assert!(!state.update_bulk_service_counter(101));

    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 0;
    telemetry.packet_train_queue_bytes = 0;
    // Consume the fast-path service observation, then begin idling.
    assert!(!state.update(telemetry, true));
    assert!(!state.update(telemetry, true));
    assert_eq!(state.bulk_idle_ticks, 1);

    assert!(!state.update_bulk_service_counter(102));
    assert_eq!(state.bulk_idle_ticks, 0);
    assert!(!state.bulk_idle_verified);
    assert!(state.bulk_active);
}

#[test]
fn confirmed_epoch_requires_five_complete_idle_ticks_before_reprobe() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = 0;
    observe_bulk_admission(&mut state, 1);
    assert!(!state.update(telemetry, true));

    telemetry.tun_ingress_bytes_per_second = 0;
    for expected in 1..5 {
        assert!(!state.update(telemetry, true));
        assert!(state.bulk_active);
        assert_eq!(state.bulk_idle_ticks, expected);
        assert!(!state.bulk_idle_verified);
    }
    assert!(!state.update(telemetry, true));
    assert!(!state.bulk_active);
    assert_eq!(state.bulk_idle_ticks, 0);
    assert!(state.bulk_idle_verified);

    telemetry.tun_ingress_bytes_per_second = 1;
    observe_bulk_admission(&mut state, 1);
    assert!(state.update(telemetry, true));
    assert!(state.bulk_active);
    assert!(!state.bulk_idle_verified);
}

#[test]
fn unconfirmed_epoch_rearms_after_two_complete_idle_ticks() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = 0;
    observe_bulk_admission(&mut state, 1);
    assert!(!state.update(telemetry, false));

    telemetry.tun_ingress_bytes_per_second = 0;
    assert!(!state.update(telemetry, false));
    assert!(state.bulk_active);
    assert_eq!(state.bulk_idle_ticks, 1);
    assert!(!state.bulk_idle_verified);
    assert!(!state.update(telemetry, false));
    assert!(!state.bulk_active);
    assert!(state.bulk_idle_verified);

    telemetry.tun_ingress_bytes_per_second = 1;
    observe_bulk_admission(&mut state, 1);
    assert!(state.update(telemetry, false));
    assert!(!state.bulk_idle_verified);
}

#[test]
fn confirmed_first_backlog_is_consumed_without_request() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = 0;
    assert!(!state.update(telemetry, true));

    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
    assert!(!state.update(telemetry, true));
    // Disabling the controller marker cannot resurrect the consumed edge.
    assert!(!state.update(telemetry, false));
}

#[test]
fn cancelled_fast_edge_preserves_request_without_fabricating_verified_idle() {
    let mut state = CapacityProbeStateV2::default();
    state.initialize_bulk_service_counter(1, 100);
    state.bulk_idle_verified = true;

    assert!(state.update_bulk_service_counter(101));
    state.cancel_bulk_service_edge();
    assert!(!state.bulk_active);
    assert!(!state.bulk_idle_verified);
    assert!(state.update_bulk_service_counter(102));
    assert!(!state.bulk_idle_verified);
    assert!(!state.update_bulk_service_counter(103));
}

#[test]
fn verified_idle_allows_one_confirmed_fast_publish() {
    let mut state = CapacityProbeStateV2::default();
    let tunables = Bbr3Tunables::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = 0;
    observe_bulk_admission(&mut state, 1);
    assert!(!state.update(telemetry, true));
    telemetry.tun_ingress_bytes_per_second = 0;
    for _ in 0..5 {
        assert!(!state.update(telemetry, true));
    }
    assert!(state.bulk_idle_verified);

    state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
    if state.update_bulk_service_counter(101) {
        publish_capacity_probe(&tunables);
    }
    assert_eq!(
        tunables.capacity_probe_generation.load(Ordering::Acquire),
        1
    );
    assert!(!state.bulk_idle_verified);
    assert!(!state.update_bulk_service_counter(102));
    assert_eq!(
        tunables.capacity_probe_generation.load(Ordering::Acquire),
        1
    );
}

#[test]
fn fast_capacity_probe_publication_is_one_release_generation() {
    let tunables = Bbr3Tunables::default();

    publish_capacity_probe(&tunables);

    assert_eq!(
        tunables.capacity_probe_generation.load(Ordering::Acquire),
        1
    );
    assert_eq!(tunables.generation.load(Ordering::Acquire), 1);
}

#[test]
fn initial_unverified_backlog_cannot_request_or_repeat_a_probe() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = 0;

    assert!(!state.update(telemetry, false));
    assert!(!state.update(telemetry, false));

    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64 - 1;
    assert!(!state.update(telemetry, false));
    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
    assert!(!state.update(telemetry, false));
    assert!(!state.update(telemetry, false));
}

#[test]
fn backlog_present_on_first_tun_tick_needs_no_extra_reprobe() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;

    assert!(!state.update(telemetry, false));
    assert!(!state.update(telemetry, false));
}

#[test]
fn bulk_probe_rearms_only_after_idle_or_path_reset() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 1;
    telemetry.packet_train_queue_bytes = 0;
    observe_bulk_admission(&mut state, 1);
    assert!(!state.update(telemetry, false));
    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
    assert!(!state.update(telemetry, false));

    // A nominally idle tick with a retained producer queue does not start
    // a new epoch. The queue must drain below the protection threshold.
    telemetry.tun_ingress_bytes_per_second = 0;
    assert!(!state.update(telemetry, false));
    assert!(state.bulk_active);
    assert_eq!(state.bulk_idle_ticks, 0);
    telemetry.packet_train_queue_bytes = 0;
    assert!(!state.update(telemetry, false));
    assert!(state.bulk_active);
    assert_eq!(state.bulk_idle_ticks, 1);
    assert!(!state.update(telemetry, false));
    assert!(!state.bulk_active);

    telemetry.tun_ingress_bytes_per_second = 1;
    observe_bulk_admission(&mut state, 1);
    assert!(state.update(telemetry, false));
    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
    assert!(!state.update(telemetry, false));

    telemetry.path_epoch += 1;
    telemetry.packet_train_queue_bytes = 0;
    assert!(!state.update(telemetry, false));
    observe_bulk_admission(&mut state, 1);
    assert!(state.update(telemetry, false));
    assert_eq!(state.bulk_idle_ticks, 0);
    telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
    assert!(!state.update(telemetry, false));
}

#[test]
fn idle_control_traffic_cannot_request_capacity_probe() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    telemetry.tun_ingress_bytes_per_second = 0;
    // Even a controller-internal train backlog is not evidence of TUN
    // demand when no TUN bytes crossed this connection.
    telemetry.packet_train_queue_bytes = 8 * TX_ADMISSION_BATCH_BYTES as u64;

    assert!(!state.update(telemetry, false));
    assert!(!state.bulk_active);
}

#[test]
fn active_tun_step_cap_release_requests_capacity_probe() {
    let mut state = CapacityProbeStateV2::default();
    let telemetry = queued_adaptive_floor_telemetry();
    assert!(!state.update(telemetry, false));

    assert!(!state.update_pacing_cap(6_500_000, true));
    assert!(state.update_pacing_cap(0, true));
    assert!(!state.update_pacing_cap(0, true));

    // A cap disappearing while the connection has no TUN demand is not
    // a capacity-discovery event.
    assert!(!state.update_pacing_cap(65_536, false));
    assert!(!state.update_pacing_cap(0, false));
}

#[test]
fn partial_initial_bulk_sample_absorbs_pacing_cap_release_without_replay() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
    assert!(!state.update_pacing_cap(6_500_000, true));
    assert!(!state.update_bulk_service_counter(101));

    assert!(!state.update(telemetry, false));
    assert!(state.initial_sample_incomplete);
    assert!(!state.update_pacing_cap_if_complete(0, true));
    assert_eq!(state.previous_pacing_cap_bytes_per_second, Some(0));

    telemetry.controller_state = 0;
    assert!(!state.update(telemetry, false));
    assert!(!state.update_pacing_cap_if_complete(0, true));
}

#[test]
fn active_loss_episode_requests_one_probe_after_two_clean_ticks() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    assert!(!state.update(telemetry, false));

    telemetry.loss_ppm = 10_000;
    assert!(!state.update_loss_episode(telemetry, false));
    assert!(state.loss_episode);

    telemetry.loss_ppm = 0;
    assert!(!state.update_loss_episode(telemetry, false));
    assert_eq!(state.consecutive_clean_loss_ticks, 1);
    assert!(state.update_loss_episode(telemetry, false));
    assert!(!state.loss_episode);
    assert_eq!(state.consecutive_clean_loss_ticks, 0);
    assert!(!state.update_loss_episode(telemetry, false));
}

#[test]
fn confirmed_controller_policer_episode_suppresses_clean_recovery_probe() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    observe_bulk_admission(&mut state, 1);
    assert!(!state.update(telemetry, false));

    telemetry.loss_ppm = 10_000;
    assert!(!state.update_loss_episode(telemetry, false));
    assert!(state.loss_episode);

    telemetry.loss_ppm = 0;
    assert!(!state.update_loss_episode(telemetry, false));
    assert_eq!(state.consecutive_clean_loss_ticks, 1);
    assert!(!state.update_loss_episode(telemetry, true));
    assert!(!state.loss_episode);
    assert!(!state.loss_signal_latched);
    assert_eq!(state.consecutive_clean_loss_ticks, 0);

    // Releasing the guard cannot publish a stale edge from the old
    // episode; a real idle/new-Bulk transition still uses `update`.
    assert!(!state.update_loss_episode(telemetry, false));
    telemetry.tun_ingress_bytes_per_second = 0;
    telemetry.packet_train_queue_bytes = 0;
    assert!(!state.update(telemetry, false));
    assert!(!state.update(telemetry, false));
    telemetry.tun_ingress_bytes_per_second = 1;
    observe_bulk_admission(&mut state, 1);
    assert!(state.update(telemetry, false));
}

#[test]
fn controller_policer_episode_activity_depends_on_transition_not_scale() {
    assert!(!controller_policer_episode_active(0));
    assert!(controller_policer_episode_active(1));

    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    assert!(!state.update(telemetry, false));
    telemetry.loss_ppm = 10_000;
    assert!(!state.update_loss_episode(telemetry, false));
    telemetry.loss_ppm = 0;
    assert!(!state.update_loss_episode(telemetry, controller_policer_episode_active(1),));
    assert!(!state.loss_episode);
}

#[test]
fn residual_or_burst_loss_arms_but_isolated_clean_and_idle_do_not_trigger() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    state.update(telemetry, false);

    telemetry.residual_loss_ppm = 10_000;
    assert!(!state.update_loss_episode(telemetry, false));
    telemetry.residual_loss_ppm = 0;
    assert!(!state.update_loss_episode(telemetry, false));
    telemetry.loss_ppm = 1;
    assert!(!state.update_loss_episode(telemetry, false));
    assert_eq!(state.consecutive_clean_loss_ticks, 0);

    telemetry.loss_ppm = 0;
    telemetry.burst_loss_cells = 3;
    assert!(!state.update_loss_episode(telemetry, false));
    assert!(!state.update_loss_episode(telemetry, false));
    assert!(state.update_loss_episode(telemetry, false));
    assert!(!state.update_loss_episode(telemetry, false));
    telemetry.burst_loss_cells = 0;

    telemetry.tun_ingress_bytes_per_second = 0;
    assert!(!state.update_loss_episode(telemetry, false));
    assert!(!state.loss_episode);
    assert_eq!(state.consecutive_clean_loss_ticks, 0);
}

#[test]
fn loss_recovery_does_not_cross_path_epochs() {
    let mut state = CapacityProbeStateV2::default();
    let mut telemetry = queued_adaptive_floor_telemetry();
    state.update(telemetry, false);
    telemetry.loss_ppm = 10_000;
    state.update_loss_episode(telemetry, false);

    telemetry.path_epoch += 1;
    telemetry.loss_ppm = 0;
    assert!(!state.update(telemetry, false));
    observe_bulk_admission(&mut state, 1);
    assert!(state.update(telemetry, false));
    assert!(!state.update_loss_episode(telemetry, false));
    assert!(!state.update_loss_episode(telemetry, false));
    assert!(!state.loss_episode);
}
