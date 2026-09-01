//! Per-adjacency autotune orchestration.

use super::*;

pub(crate) async fn tuner_loop(
    connection: Connection,
    metrics: Arc<RuntimeMetrics>,
    sender: watch::Sender<Option<TuneDecisionV2>>,
    runtime_state: Arc<V2RuntimeState>,
    ticket_partition: String,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut capacity_probe_edge_interval = tokio::time::interval(CAPACITY_PROBE_EDGE_INTERVAL);
    capacity_probe_edge_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let bounds = AutoTuneBoundsV2::default();
    let tuner = AutoTunerV2::new(bounds, 1);
    let objective = match runtime_state.autotune.objective {
        AutotuneObjective::Balanced => Objective::Balanced,
        AutotuneObjective::Throughput => Objective::Throughput,
        AutotuneObjective::Latency => Objective::Latency,
    };
    let forced_action = autotune_force_from_env()?;
    let learner_mode = if forced_action.is_some() {
        LearnerModeV2::Off
    } else {
        match runtime_state.autotune.mode {
            AutotuneMode::Off => LearnerModeV2::Off,
            AutotuneMode::Shadow => LearnerModeV2::Shadow,
            AutotuneMode::On => LearnerModeV2::On,
        }
    };
    // `native` is the explicit host-side conservative rules backend (no
    // learner). `builtin` is the in-process `PolicySpecV1` core learner;
    // only external absolute `.wasm` components enter the verified Wasmtime
    // loader. External JSON artifacts are gone.
    // Utility is host-computed with the canonical objective weights in all
    // cases — a component carries no weight bag of its own.
    let selection = runtime_state.autotune.policy.as_str();
    let wasm_selection = is_external_wasm_policy_selection(selection);
    let peer_hash = policy_peer_hash(connection.remote_id().as_bytes());
    let utility_weights = objective.weights();
    let mut policy_source = selection.to_owned();
    // Whole-file digest of the live component, for reload change detection.
    let mut wasm_seen_hash: Option<[u8; 32]> = None;
    let live_slot = if wasm_selection {
        let path = std::path::Path::new(selection);
        match load_wasm_live_slot(&runtime_state, path) {
            Ok((slot, file_hash)) => {
                info!(
                    peer = %connection.remote_id(),
                    policy_id = %slot.identity().policy_id,
                    policy_version = %slot.identity().policy_version,
                    state_schema = slot.identity().state_schema,
                    module_digest = %slot.module_digest(),
                    "loaded WASM autotune policy"
                );
                wasm_seen_hash = Some(file_hash);
                slot
            }
            Err(error) => {
                warn!(
                    configured = %selection,
                    error = %format_args!("{error:#}"),
                    "rejected external V2 WASM autotune policy and fell back to the native-core builtin policy"
                );
                policy_source = crate::protocol::v2::policy::BUILTIN_POLICY_SOURCE_V2.to_owned();
                builtin_core_slot(learner_mode)
            }
        }
    } else {
        non_wasm_live_slot(selection, learner_mode, &mut policy_source)
    };
    let mut tick_config = PolicyTickConfigV1::new(objective, learner_mode);
    tick_config.forced = forced_action;
    tick_config.max_egress_bytes_per_second = runtime_state.max_egress_bytes_per_second;
    tick_config.state_cap_bytes =
        u32::try_from(runtime_state.autotune.wasm.maximum_state_bytes).unwrap_or(u32::MAX);
    tick_config.peer_hash = peer_hash;
    let mut tick = PolicyTickV1::new(tuner, live_slot, utility_weights, tick_config);
    info!(
        policy_id = %tick.live().identity().policy_id,
        policy_version = %tick.live().identity().policy_version,
        %policy_source,
        backend = %tick.live().status().backend,
        state_schema = tick.live().identity().state_schema,
        module_digest = %tick.live().module_digest(),
        ?objective,
        mode = ?runtime_state.autotune.mode,
        memory = runtime_state.autotune.memory,
        "loaded V2 autotune policy"
    );
    // Optional shadow policy (`.wasm` only since Phase 6): observes the live
    // input without influencing the wire. Reloaded on change like the live
    // component, minus the warmup stage — a shadow is already off-wire.
    let shadow_selection = runtime_state
        .autotune
        .shadow_policy
        .as_deref()
        .filter(|path| is_external_wasm_policy_path(path));
    let mut last_shadow_reload_error: Option<String> = None;
    let mut shadow_seen_hash: Option<[u8; 32]> = None;
    if let Some(shadow_path) = shadow_selection {
        match load_wasm_backend(&runtime_state, shadow_path) {
            Ok((backend, file_hash)) => {
                let shadow = shadow_evaluator_for_backend(backend, objective, peer_hash);
                info!(
                    peer = %connection.remote_id(),
                    shadow_policy_id = %shadow.policy_id(),
                    source = %shadow_path.display(),
                    "loaded V2 WASM shadow autotune policy"
                );
                shadow_seen_hash = Some(file_hash);
                tick.set_shadow(Some(shadow));
            }
            Err(error) => {
                let message = format!("{error:#}");
                warn!(
                    source = %shadow_path.display(),
                    error = %message,
                    "ignored invalid V2 WASM shadow autotune policy"
                );
                last_shadow_reload_error = Some(message);
            }
        }
    }
    let peer_name = connection.remote_id().to_string();
    let state_store = runtime_state.autotune.memory.then(|| {
        PolicyStateStoreV1::new(
            &runtime_state.autotune_state_dir,
            Duration::from_secs(runtime_state.autotune.wasm.state_flush_interval_secs),
            usize::try_from(runtime_state.autotune.wasm.maximum_state_bytes).unwrap_or(usize::MAX),
        )
    });
    let mut persistence = PolicyPersistenceV1::new(state_store, peer_name, Instant::now());
    persistence.restore(tick.live_mut());
    let mut last_policy_fault: Option<PolicyFaultV1> = None;
    if let Some(forced_action) = forced_action {
        info!(
            peer = %connection.remote_id(),
            ?forced_action,
            "enabled guarded IRONET_AUTOTUNE_FORCE experiment"
        );
    }
    let initial_sample_at = Instant::now();
    let mut telemetry_window =
        PathTelemetryWindowV2::capture(&connection, &metrics, initial_sample_at);
    let mut remote_feedback = RemoteFeedbackWindowV2::capture(&metrics, Instant::now());
    let mut adaptive_cwnd_floor_state = AdaptiveCwndFloorStateV2::default();
    let mut capacity_probe_state = CapacityProbeStateV2::default();
    capacity_probe_state.initialize_bulk_service_counter(
        telemetry_window.epoch,
        metrics.bulk_service_bytes.load(Ordering::Relaxed),
    );
    capacity_probe_state
        .initialize_bulk_admission_counter(metrics.bulk_admission_bytes.load(Ordering::Relaxed));
    let mut reload =
        PolicyReloadStateV1::new(wasm_seen_hash, shadow_seen_hash, last_shadow_reload_error);
    interval.tick().await;
    capacity_probe_edge_interval.tick().await;
    loop {
        let full_policy_tick = tokio::select! {
            biased;
            _ = interval.tick() => true,
            _ = capacity_probe_edge_interval.tick() => false,
        };
        if !full_policy_tick {
            let bulk_service_counter = metrics.bulk_service_bytes.load(Ordering::Relaxed);
            let bulk_admission_counter = metrics.bulk_admission_bytes.load(Ordering::Relaxed);
            let path_sample = selected_path_sample(&connection).ok();
            let path_matches = path_sample.as_ref().is_some_and(|sample| {
                fast_capacity_probe_path_matches(&telemetry_window.identity, &sample.identity)
            });
            let capacity_probe_reason = path_matches.then(|| {
                let reactivated_after_idle =
                    capacity_probe_state.update_bulk_service_counter(bulk_service_counter);
                capacity_probe_state.update_bulk_admission_counter(bulk_admission_counter);
                if reactivated_after_idle {
                    Some("bulk_service_reactivation")
                } else {
                    path_sample.as_ref().and_then(|sample| {
                        let controller_state = sample
                            .controller_snapshot
                            .map_or(0, |snapshot| snapshot.state);
                        let policer_episode_active = controller_policer_episode_active(
                            sample.controller_policer_pacing_transitions,
                        );
                        capacity_probe_state
                            .sustained_initial_bulk_requires_probe(
                                controller_state,
                                policer_episode_active,
                            )
                            .then_some("initial_bulk_demand")
                    })
                }
            });
            if let Some(reason) = capacity_probe_reason.flatten() {
                let published = path_sample
                    .as_ref()
                    .and_then(|sample| sample.controller_tunables.as_ref())
                    .is_some_and(|tunables| {
                        publish_capacity_probe(tunables);
                        true
                    });
                if published {
                    debug!(
                        peer = %connection.remote_id(),
                        reason,
                        bulk_service_edges = capacity_probe_state.initial_bulk_service_edges,
                        bulk_service_bytes = capacity_probe_state.initial_bulk_serviced_bytes,
                        bulk_admission_edges = capacity_probe_state.initial_bulk_admission_edges,
                        bulk_admission_bytes = capacity_probe_state.initial_bulk_admitted_bytes,
                        "published V2 BBR capacity probe"
                    );
                } else {
                    // The normal one-second telemetry path remains the
                    // fallback if a selected BBR path was transiently absent.
                    capacity_probe_state.cancel_bulk_service_edge();
                }
            }
            continue;
        }
        let sampled_at = Instant::now();
        reload.advance();
        if wasm_selection {
            let live_finished = matches!(
                &reload.live_phase,
                LiveReloadPhaseV1::Loading(handle) if handle.is_finished()
            );
            if live_finished {
                let phase = std::mem::replace(&mut reload.live_phase, LiveReloadPhaseV1::Idle);
                let LiveReloadPhaseV1::Loading(handle) = phase else {
                    unreachable!("finished live reload must be loading");
                };
                match handle.await {
                    Ok(Ok(Some((backend, file_hash)))) => {
                        reload.live_seen_hash = Some(file_hash);
                        let accepts = backend.manifest().state_schema_accepts.clone();
                        let new_policy_id = backend.identity().policy_id.clone();
                        let digest = backend
                            .identity()
                            .digest
                            .map(|digest| encode_digest(&digest))
                            .unwrap_or_default();
                        let slot = PolicySlotV1::new(Box::new(backend), None, digest.clone());
                        let mut evaluator = ShadowEvaluatorV2::from_slot(
                            slot,
                            objective.weights(),
                            objective,
                            new_policy_id.clone(),
                            digest,
                        );
                        evaluator.set_peer_hash(peer_hash);
                        reload.live_phase = LiveReloadPhaseV1::Warming(Box::new(WasmWarmupV1 {
                            evaluator,
                            accepts,
                            healthy_ticks: 0,
                        }));
                        info!(
                            peer = %connection.remote_id(),
                            new_policy_id = %new_policy_id,
                            source = %runtime_state.autotune.policy,
                            warmup_ticks = WASM_WARMUP_TICKS,
                            "V2 WASM autotune policy candidate entered shadow warmup"
                        );
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        let message = format!("{error:#}");
                        if reload.last_live_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %runtime_state.autotune.policy,
                                error = %message,
                                "retained last known-good V2 WASM autotune policy"
                            );
                            reload.last_live_error = Some(message);
                        }
                    }
                    Err(error) => {
                        let message = format!("WASM policy load task failed: {error}");
                        if reload.last_live_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %runtime_state.autotune.policy,
                                error = %message,
                                "retained last known-good V2 WASM autotune policy"
                            );
                            reload.last_live_error = Some(message);
                        }
                    }
                }
            }
            if reload.scan_due() && matches!(reload.live_phase, LiveReloadPhaseV1::Idle) {
                let runtime = runtime_state.clone();
                let path = std::path::PathBuf::from(&runtime_state.autotune.policy);
                let seen_hash = reload.live_seen_hash;
                reload.live_phase =
                    LiveReloadPhaseV1::Loading(tokio::task::spawn_blocking(move || {
                        load_changed_wasm_backend(&runtime, &path, seen_hash)
                    }));
            }
        }
        if let Some(shadow_path) = shadow_selection {
            let shadow_finished = matches!(
                &reload.shadow_phase,
                ShadowReloadPhaseV1::Loading(handle) if handle.is_finished()
            );
            if shadow_finished {
                let phase = std::mem::replace(&mut reload.shadow_phase, ShadowReloadPhaseV1::Idle);
                let ShadowReloadPhaseV1::Loading(handle) = phase else {
                    unreachable!("finished shadow reload must be loading");
                };
                match handle.await {
                    Ok(Ok(Some((backend, file_hash)))) => {
                        reload.shadow_seen_hash = Some(file_hash);
                        let shadow = shadow_evaluator_for_backend(backend, objective, peer_hash);
                        info!(
                            peer = %connection.remote_id(),
                            new_shadow_policy_id = %shadow.policy_id(),
                            source = %shadow_path.display(),
                            "hot-switched V2 WASM shadow autotune policy at sample boundary"
                        );
                        tick.set_shadow(Some(shadow));
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        let message = format!("{error:#}");
                        if reload.last_shadow_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %shadow_path.display(),
                                error = %message,
                                "retained last known-good V2 WASM shadow autotune policy"
                            );
                            reload.last_shadow_error = Some(message);
                        }
                    }
                    Err(error) => {
                        let message = format!("WASM shadow policy load task failed: {error}");
                        if reload.last_shadow_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %shadow_path.display(),
                                error = %message,
                                "retained last known-good V2 WASM shadow autotune policy"
                            );
                            reload.last_shadow_error = Some(message);
                        }
                    }
                }
            }
            if reload.scan_due() && matches!(reload.shadow_phase, ShadowReloadPhaseV1::Idle) {
                let runtime = runtime_state.clone();
                let path = shadow_path.to_path_buf();
                let seen_hash = reload.shadow_seen_hash;
                reload.shadow_phase =
                    ShadowReloadPhaseV1::Loading(tokio::task::spawn_blocking(move || {
                        load_changed_wasm_backend(&runtime, &path, seen_hash)
                    }));
            }
        }
        let sample_elapsed =
            sampled_at.saturating_duration_since(telemetry_window.previous_sample_at);
        let current = connection.stats();
        let path = match selected_path_sample(&connection) {
            Ok(sample) => {
                if telemetry_window.failures != 0 {
                    info!(
                        peer = %connection.remote_id(),
                        failures = telemetry_window.failures,
                        "V2 path telemetry recovered without replacing the logical session"
                    );
                    telemetry_window.failures = 0;
                }
                sample
            }
            Err(error) => {
                telemetry_window.failures = telemetry_window.failures.saturating_add(1);
                let decision = tick.fallback_for_missing_telemetry();
                metrics
                    .receive_buffer_bytes
                    .store(decision.receive_buffer_bytes as u64, Ordering::Relaxed);
                if sender.send(Some(decision)).is_err() {
                    persistence.flush(tick.live_mut(), sampled_at)?;
                    return Ok(());
                }
                if telemetry_window.failures == 1 || telemetry_window.failures.is_multiple_of(10) {
                    warn!(
                        peer = %connection.remote_id(),
                        failures = telemetry_window.failures,
                        path_epoch = decision.path_epoch,
                        reason = ?decision.reason,
                        %error,
                        "V2 path telemetry unavailable; applied bounded conservative tuning"
                    );
                }
                let current_sample_counters =
                    SampleCounterSnapshot::capture(&metrics, current.udp_tx.bytes);
                telemetry_window.previous = current;
                telemetry_window.previous_sample_at = sampled_at;
                telemetry_window.sample_counters = current_sample_counters;
                continue;
            }
        };
        let SelectedPathSampleV2 {
            identity,
            reliability,
            rtt,
            congestion_window_bytes,
            controller_pacing_rate_bytes_per_second,
            controller_send_quantum_bytes,
            controller_policer_pacing_transitions,
            controller_snapshot,
            controller_tunables,
        } = path;
        let route_capacity_bytes_per_second = controller_snapshot
            .map(|snapshot| snapshot.bw.max(snapshot.max_bw))
            .filter(|capacity| *capacity != 0)
            .or(controller_pacing_rate_bytes_per_second)
            .unwrap_or(0);
        metrics.route_capacity_bps.store(
            route_capacity_bytes_per_second.saturating_mul(8),
            Ordering::Relaxed,
        );
        // PathId is a QUIC controller identity, while `path_identity` below is
        // deliberately a stable network-locator epoch. noq may recycle PathId
        // without changing the locator, so never cache its path-local BBR
        // handle across samples.
        let bbr_tunables = controller_tunables;
        if identity != telemetry_window.identity {
            let migrated = !telemetry_window.identity.is_empty();
            let previous_identity = std::mem::replace(&mut telemetry_window.identity, identity);
            if migrated {
                telemetry_window.epoch = telemetry_window.epoch.wrapping_add(1).max(1);
            }
            telemetry_window.previous_guard_transitions =
                controller_snapshot.map_or(0, |snapshot| snapshot.guard_transitions);
            if migrated {
                info!(
                    path_epoch = telemetry_window.epoch,
                    ?reliability,
                    previous_path = %previous_identity,
                    selected_path = %telemetry_window.identity,
                    "V2 QUIC path migrated without replacing the logical session"
                );
            }
        }
        let minimum_rtt = controller_snapshot
            .map(|snapshot| snapshot.min_rtt)
            .filter(|minimum| !minimum.is_zero() && *minimum != Duration::MAX)
            .unwrap_or(rtt);
        metrics.repair_minimum_age_micros.store(
            repair_minimum_age_for_rtt(rtt)
                .as_micros()
                .min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        let sent_packets = counter_delta(
            current.udp_tx.datagrams,
            telemetry_window.previous.udp_tx.datagrams,
        );
        let received_packets = counter_delta(
            current.udp_rx.datagrams,
            telemetry_window.previous.udp_rx.datagrams,
        );
        let lost_packets =
            counter_delta(current.lost_packets, telemetry_window.previous.lost_packets);
        // `udp_tx.datagrams` already counts every attempted wire datagram,
        // including the ones later declared lost. Adding `lost_packets` again
        // biases the denominator and under-reports the erasure rate.
        let loss_ppm = ratio_per_million(lost_packets, sent_packets);
        let sent_bytes =
            counter_delta(current.udp_tx.bytes, telemetry_window.previous.udp_tx.bytes);
        let received_bytes =
            counter_delta(current.udp_rx.bytes, telemetry_window.previous.udp_rx.bytes);
        let sent_bytes_per_second = rate_per_second(sent_bytes, sample_elapsed);
        let received_bytes_per_second = rate_per_second(received_bytes, sample_elapsed);
        let current_sample_counters =
            SampleCounterSnapshot::capture(&metrics, current.udp_tx.bytes);
        let sample_delta =
            current_sample_counters.saturating_delta(telemetry_window.sample_counters);
        let real_bytes = current_sample_counters.real_bytes;
        let real_delta = sample_delta.real_bytes;
        let tun_ingress_records_delta = sample_delta.tun_ingress_records;
        let tun_ingress_bytes_delta = sample_delta.tun_ingress_bytes;
        let gso_input_bytes_delta = sample_delta.gso_input_bytes;
        let reassembly_pressure_evictions_delta = sample_delta.reassembly_pressure_evictions;
        let train_build_bytes_per_second =
            rate_per_second(sample_delta.train_build_bytes, sample_elapsed);
        let bulk_preemption_delta = sample_delta.bulk_preemptions;
        let bulk_preemption_delay_average_micros = sample_delta
            .bulk_preemption_delay_micros
            .checked_div(bulk_preemption_delta)
            .unwrap_or_default();
        let tun_ingress_bytes_per_second = rate_per_second(tun_ingress_bytes_delta, sample_elapsed);
        let average_record_bytes = tun_ingress_bytes_delta
            .checked_div(tun_ingress_records_delta)
            .unwrap_or_default();
        let gso_ingress_ratio_ppm =
            ratio_per_million(gso_input_bytes_delta, tun_ingress_bytes_delta);
        let train_queue_bytes = metrics.train_queue_bytes.load(Ordering::Relaxed);
        let latency_queue_bytes = metrics.latency_queue_bytes.load(Ordering::Relaxed);
        let cpu_utilization_per_mille = runtime_state
            .cpu_utilization_per_mille
            .load(Ordering::Relaxed)
            .min(1_000) as u16;
        let remote = remote_feedback.sample(&metrics, sampled_at);
        let latency_sojourn_delta = sample_delta.latency_sojourn;
        let latency_sojourn_p50_micros = histogram_percentile_micros(&latency_sojourn_delta, 50);
        let latency_sojourn_p95_micros = histogram_percentile_micros(&latency_sojourn_delta, 95);
        let latency_sojourn_p99_micros = histogram_percentile_micros(&latency_sojourn_delta, 99);
        let latency_queue_recently_nonempty =
            latency_queue_bytes != 0 || latency_sojourn_delta.iter().any(|count| *count != 0);
        let controller_guard_transitions =
            controller_snapshot.map_or(0, |snapshot| snapshot.guard_transitions);
        let controller_guard_transitions_delta = controller_guard_transitions
            .saturating_sub(telemetry_window.previous_guard_transitions);
        telemetry_window.previous_guard_transitions = controller_guard_transitions;
        let controller_tunables_generation = bbr_tunables
            .as_ref()
            .map_or(0, |tunables| tunables.generation.load(Ordering::Relaxed));
        let controller_clamped_writes = bbr_tunables.as_ref().map_or(0, |tunables| {
            tunables.clamped_writes.load(Ordering::Relaxed)
        });
        let telemetry = PathTelemetryV2 {
            path_epoch: telemetry_window.epoch,
            reliability,
            rtt,
            min_rtt: minimum_rtt,
            queue_delay: rtt.saturating_sub(minimum_rtt),
            loss_ppm,
            burst_loss_cells: remote.burst_loss_cells,
            reorder_ppm: remote.reorder_ppm,
            receiver_goodput_bytes_per_second: remote.receiver_goodput_bytes_per_second,
            residual_loss_ppm: remote.residual_loss_ppm,
            latency_sojourn_p95_micros,
            latency_sojourn_p50_micros,
            latency_sojourn_p99_micros,
            latency_queue_recently_nonempty,
            delivery_rate_bytes_per_second: sent_bytes_per_second,
            controller_pacing_rate_bytes_per_second: controller_pacing_rate_bytes_per_second
                .unwrap_or_default(),
            controller_send_quantum_bytes: controller_send_quantum_bytes.unwrap_or_default(),
            controller_state: controller_snapshot.map_or(0, |snapshot| snapshot.state),
            controller_bw_bytes_per_second: controller_snapshot.map_or(0, |snapshot| snapshot.bw),
            controller_inflight_longterm_bytes: controller_snapshot
                .map_or(0, |snapshot| snapshot.inflight_longterm),
            controller_guard_transitions_delta,
            controller_app_limited: controller_snapshot
                .is_some_and(|snapshot| snapshot.app_limited_in_round),
            controller_tunables_generation,
            controller_params_generation: controller_snapshot
                .map_or(0, |snapshot| snapshot.params_generation),
            controller_clamped_writes,
            receive_rate_bytes_per_second: received_bytes_per_second,
            // Receive coalescing is driven by the busier direction. This is
            // essential for asymmetric paths: a gateway receiving a Bulk
            // stream may transmit little more than QUIC ACKs itself.
            packets_per_second: sent_packets.max(received_packets),
            tun_ingress_bytes_per_second,
            average_record_bytes,
            gso_ingress_ratio_ppm,
            packet_train_queue_bytes: train_queue_bytes,
            latency_queue_bytes,
            reassembly_pressure_evictions: reassembly_pressure_evictions_delta,
            remote_expired_stripes_delta: remote.expired_stripes_delta,
            train_build_bytes_per_second,
            bulk_preemption_delay_average_micros,
            cpu_utilization_per_mille,
            wasted_parity_per_mille: remote.wasted_parity_per_mille,
            fec_recovery_per_mille: remote.fec_recovery_per_mille,
            repair_hit_per_mille: remote.repair_hit_per_mille,
            repair_completed_requests: remote.repair_completed_requests,
            repair_response_latency: remote.repair_response_latency,
            real_traffic_bytes_per_second: rate_per_second(real_delta, sample_elapsed),
        };
        let controller_policer_episode_active =
            controller_policer_episode_active(controller_policer_pacing_transitions);
        let bulk_capacity_probe =
            capacity_probe_state.update(telemetry, controller_policer_episode_active);
        let loss_recovery_probe = capacity_probe_state
            .update_loss_episode_if_complete(telemetry, controller_policer_episode_active);
        let wire_cost = current_sample_counters
            .utility_tx_bytes
            .delta(telemetry_window.sample_counters.utility_tx_bytes)
            .breakdown()
            .wire_cost();
        // Baseline -> PolicyInputV1 -> backend decide -> guardrails ->
        // EffectiveActionV1 -> TuneDecisionV2 (and the shadow evaluation),
        // see `protocol::v2::policy_tick`.
        // Plan section 9: read the node egress view for this tick before the
        // pipeline runs; publish the guarded request afterwards. Both are
        // lock-protected shared state, so a slow or faulting guest on
        // another peer can never block this tick.
        let egress_peer_key = tick.config().peer_hash;
        tick.set_egress_view(
            runtime_state
                .egress_coordinator
                .view(egress_peer_key, sampled_at),
        );
        let mut outcome = tick.run(telemetry, &wire_cost, sampled_at);
        let adaptive_cwnd_floor_bytes = finalize_bbr3_effective_with_state(
            &mut adaptive_cwnd_floor_state,
            telemetry,
            congestion_window_bytes,
            &mut outcome.effective.bbr,
        );
        let pacing_cap_release_probe = capacity_probe_state.update_pacing_cap_if_complete(
            outcome.effective.bbr.pacing_cap_bytes_per_second,
            telemetry.tun_ingress_bytes_per_second > 0,
        );
        // Bulk and loss state machines consume prohibited edges at their
        // source. Verified-idle Bulk epochs and explicit cap releases retain
        // independent authority to restart discovery.
        let request_capacity_probe =
            bulk_capacity_probe || loss_recovery_probe || pacing_cap_release_probe;
        let egress_requested_bytes_per_second =
            outcome.effective.egress.desired_rate_bytes_per_second;
        runtime_state.egress_coordinator.publish(
            egress_peer_key,
            outcome.effective.egress,
            sampled_at,
        );
        // Plan section 8.3 shadow warmup: the candidate observes this tick's
        // live input without influencing the wire; any fault aborts it and
        // `WASM_WARMUP_TICKS` consecutive healthy ticks promote it to live.
        let live_phase = std::mem::replace(&mut reload.live_phase, LiveReloadPhaseV1::Idle);
        if let LiveReloadPhaseV1::Warming(mut warmup) = live_phase {
            let evaluation = warmup.evaluator.observe(
                sampled_at,
                tick.tuner(),
                &telemetry,
                &wire_cost,
                outcome.baseline,
            );
            if let Some(fault) = evaluation.fault {
                warn!(
                    peer = %connection.remote_id(),
                    policy_id = %warmup.evaluator.policy_id(),
                    healthy_ticks = warmup.healthy_ticks,
                    %fault,
                    "aborted V2 WASM policy warmup; retained last known-good"
                );
            } else {
                warmup.healthy_ticks = warmup.healthy_ticks.saturating_add(1);
                if warmup.healthy_ticks >= WASM_WARMUP_TICKS {
                    let policy_id = warmup.evaluator.policy_id().to_owned();
                    let WasmWarmupV1 {
                        evaluator,
                        accepts,
                        healthy_ticks: _,
                    } = *warmup;
                    let (backend, probe, digest) = evaluator.into_slot().into_backend();
                    if let Err(error) = persistence.flush(tick.live_mut(), sampled_at) {
                        warn!(
                            peer = %connection.remote_id(),
                            %error,
                            "failed persisting V2 policy state before hot switch"
                        );
                    }
                    let kept_state =
                        tick.replace_live(backend, probe, digest, objective.weights(), &accepts);
                    if !kept_state {
                        persistence.restore(tick.live_mut());
                    }
                    reload.last_live_error = None;
                    info!(
                        peer = %connection.remote_id(),
                        new_policy_id = %policy_id,
                        source = %runtime_state.autotune.policy,
                        kept_state,
                        warmup_ticks = WASM_WARMUP_TICKS,
                        "promoted V2 WASM autotune policy after shadow warmup"
                    );
                } else {
                    reload.live_phase = LiveReloadPhaseV1::Warming(warmup);
                }
            }
        } else {
            reload.live_phase = live_phase;
        }
        let decision = outcome.decision;
        if outcome.fault != last_policy_fault {
            match outcome.fault {
                Some(fault) => {
                    let health = tick.live().health();
                    warn!(
                        peer = %connection.remote_id(),
                        %fault,
                        health = ?health.state,
                        faults_total = health.faults_total,
                        "V2 policy backend fault; applied the host baseline"
                    );
                }
                None => info!(
                    peer = %connection.remote_id(),
                    "V2 policy backend recovered"
                ),
            }
            last_policy_fault = outcome.fault;
        }
        if let Some(tunables) = bbr_tunables.as_deref() {
            publish_bbr3_effective(tunables, &outcome.effective.bbr, request_capacity_probe);
        }
        let utility = outcome.utility;
        let learner_trace = outcome.trace;
        let shadow_evaluation = outcome.shadow;
        let shadow_policy_id = tick.shadow().map(|shadow| shadow.policy_id().to_owned());
        let live_policy_id = tick.live().identity().policy_id.clone();
        let egress_assigned_bytes_per_second = tick.egress_view().assigned_rate_bytes_per_second;
        runtime_state.publish_tune_status(
            connection.remote_id(),
            TuneStatusSampleV2 {
                decision,
                utility,
                learner: learner_trace,
                policy_id: &live_policy_id,
                policy_source: &policy_source,
                shadow_policy_id: shadow_policy_id.as_deref(),
                shadow: shadow_evaluation,
                live: tick.live().status(),
                shadow_slot: tick.shadow().map(|shadow| shadow.slot().status()),
                egress_requested_bytes_per_second,
                egress_assigned_bytes_per_second,
            },
        );
        if tracing::enabled!(target: "ironet::autotune", tracing::Level::DEBUG) {
            let sampled_unix_micros = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
            let record = autotune_tap_record(
                connection.remote_id(),
                &ticket_partition,
                AutotuneTapSampleV2 {
                    sampled_unix_micros,
                    sample_elapsed,
                    telemetry,
                    decision,
                    utility,
                    wire_cost,
                    force_applied: forced_action.is_some(),
                    learner: Some(learner_trace),
                    policy_id: &live_policy_id,
                    policy_source: &policy_source,
                    shadow_policy_id: shadow_policy_id.as_deref(),
                    shadow: shadow_evaluation,
                    path_identity: &telemetry_window.identity,
                    controller_cwnd_bytes: congestion_window_bytes,
                    adaptive_cwnd_floor_bytes,
                },
            );
            debug!(
                target: "ironet::autotune",
                record = %record,
                "V2 autotune tap"
            );
        }
        metrics
            .receive_buffer_bytes
            .store(decision.receive_buffer_bytes as u64, Ordering::Relaxed);
        metrics
            .reassembly_budget_bytes
            .store(decision.reassembly_budget_bytes as u64, Ordering::Relaxed);
        metrics
            .active_train_budget
            .store(u64::from(decision.active_train_budget), Ordering::Relaxed);
        metrics.repair_wait_policy.store(
            decision.repair_wait_policy.to_metrics_code(),
            Ordering::Relaxed,
        );
        if sender.send(Some(decision)).is_err() {
            persistence.flush(tick.live_mut(), sampled_at)?;
            return Ok(());
        }
        if let Err(error) = persistence.flush_if_due(tick.live_mut(), sampled_at) {
            warn!(
                peer = %connection.remote_id(),
                %error,
                "failed persisting V2 policy state"
            );
        }
        super::diagnostics::emit_periodic_status(super::diagnostics::PeriodicStatus {
            peer: connection.remote_id(),
            decision,
            telemetry,
            metrics: &metrics,
            previous: &mut telemetry_window.status_counters,
            udp_tx_bytes: current.udp_tx.bytes,
            real_bytes,
            ticket_partition: &ticket_partition,
        });
        telemetry_window.previous = current;
        telemetry_window.previous_sample_at = sampled_at;
        telemetry_window.sample_counters = current_sample_counters;
    }
}
