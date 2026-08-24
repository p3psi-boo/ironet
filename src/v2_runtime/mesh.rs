//! V2 mesh dataplane orchestration, authenticated presence, and OAM handling.

use std::{
    collections::{VecDeque, hash_map::Entry},
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, bail, ensure};
use arc_swap::ArcSwap;
use bytes::Bytes;
use ipnet::IpNet;
use iroh::{Endpoint, EndpointId, SecretKey};
use rustc_hash::FxHashMap as HashMap;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
};
use tracing::{debug, info, warn};
use tun_rs::VIRTIO_NET_HDR_LEN;

use super::{
    QUIC_WIRE_VERSION, ShutdownFuture, TUN_REGULAR_INPUT_BYTES, V2RuntimeConfig, V2RuntimeState,
    autotune::{selected_direct_addresses, selected_path_cost, ticket_partition_label, tuner_loop},
    connection::{PeerSessionV2, establish_mesh_adjacencies},
    cpu_sampler_loop,
    dataplane::{
        CLASSIFIER_IDLE, CoverShaperV2, IngressReadyOrderV2, MAX_CLASSIFIERS,
        PrioritySendArbiterV2, TUN_INPUT_SLOTS, TUN_PRIORITY_INPUT_SLOTS, TX_ADMISSION_BATCH_BYTES,
        TX_LATENCY_ADMISSION_HIGH_WATER_BYTES, TunIngressRecordV2, TxControl,
        adaptive_repair_minimum_age, admission_saturated, apply_receive_buffer_target,
        drain_tun_ingress_batch, effective_tx_tuning, flow_id, ingress_ready_order,
        minimum_receive_buffer_bytes, prioritized_tun_reader, route_loop, tx_admission_high_water,
        unix_secs, write_reassembled,
    },
    host_network::{configure_mesh_tunnel, local_overlay_addresses, reconcile_v2_nat},
    telemetry::{RuntimeMetrics, TunIngressBatchV2, increment_sampled_counter},
};
use crate::{
    derp::DerpTransport,
    packet::{FlowKey, ip_hop_limit_validated},
    protocol::v2::{
        cell::TrafficClass,
        classifier::{ClassifierConfig, FlowClassifier},
        cover::CoverPaddingV2,
        dataplane::{ForwardAdmissionV2, MAX_REPAIR_REQUESTS_PER_TICK, V2ControlRx, V2Rx, V2Tx},
        feedback::FecFeedbackV2,
        gso::encode_train_record_observed,
        presence::{
            PresenceBodyV2, PresenceDirectoryV2, PresenceLinkV2, PresenceUpdateV2, SignedPresenceV2,
        },
        reassembly::ReassemblyOutput,
        repair::{RepairControlV2, RepairResponseV2},
        routing::{
            AdjacencyIdV2, DataplaneSnapshotStoreV2, DataplaneSnapshotV2, LabelActionV2,
            OamControlV2, OamPathMtuExceededV2, ResolvedRouteV2, RouteAdvertisementV2,
            RouteLabelV2, TransitDispositionV2,
        },
        scheduler::SchedulerLimits,
        train::TrainRecord,
        tuning::{AutoTuneBoundsV2, TuneDecisionV2},
    },
    trace::{OverlayTraceOamEvent, TraceProbeTag, v2_trace_probe_tag},
    tunnel::OverlayTunnel,
};

const TRACE_TRAIN_REGISTRATION_TTL: Duration = Duration::from_secs(120);
const MAX_TRACE_TRAIN_REGISTRATIONS: usize = 4_096;
const MAX_PATH_MTU_CONSTRAINTS: usize = 4_096;

/// Control-plane view owned by the V2 runtime. It deliberately exposes V2
/// protocol identity and connection health without translating through the
/// legacy runtime's counter graph.
#[derive(Debug, Clone, Copy)]
pub(super) struct PendingTraceTrainV2 {
    request_id: u64,
    target: IpAddr,
    registered_at: Instant,
}

impl V2RuntimeState {
    fn register_trace_train(&self, route: ResolvedRouteV2, train_id: u64, tag: TraceProbeTag) {
        let now = Instant::now();
        let mut pending = self
            .trace_trains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|_, value| {
            now.saturating_duration_since(value.registered_at) < TRACE_TRAIN_REGISTRATION_TTL
        });
        if pending.len() >= MAX_TRACE_TRAIN_REGISTRATIONS
            && let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, value)| value.registered_at)
                .map(|(key, _)| *key)
        {
            pending.remove(&oldest);
        }
        pending.insert(
            (route.route_epoch, route.route_label.0, train_id),
            PendingTraceTrainV2 {
                request_id: tag.request_id,
                target: tag.target,
                registered_at: now,
            },
        );
    }

    fn publish_ttl_expired(&self, oam: &crate::protocol::v2::routing::OamTtlExpiredV2) {
        let mut trace_trains = self
            .trace_trains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = trace_trains.remove(&(oam.route_epoch, oam.route_label.0, oam.train_id));
        let Some(pending) = pending else {
            return;
        };
        trace_trains.retain(|_, value| value.request_id != pending.request_id);
        drop(trace_trains);
        if pending.registered_at.elapsed() >= TRACE_TRAIN_REGISTRATION_TTL {
            return;
        }
        let Ok(reporter_id) = EndpointId::from_bytes(&oam.reporter) else {
            return;
        };
        let mesh = self
            .mesh
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(node) = mesh
            .nodes
            .iter()
            .find(|node| node.endpoint_id == reporter_id.to_string())
        else {
            return;
        };
        let Some(reporter_address) = node
            .node_addresses
            .iter()
            .map(IpNet::addr)
            .find(|address| address.is_ipv4() == pending.target.is_ipv4())
        else {
            return;
        };
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("endpoint_id".to_owned(), reporter_id.to_string());
        metadata.insert("overlay_hops".to_owned(), oam.traversed_hops.to_string());
        let _ = self.trace_events.send(OverlayTraceOamEvent {
            request_id: pending.request_id,
            reporter_address,
            reporter: crate::config::NodeInfo {
                name: reporter_id.to_string(),
                description: Some("V2 overlay transit node".to_owned()),
                metadata,
            },
        });
    }
}

#[derive(Debug)]
enum MeshTxCommandV2 {
    Records {
        flow_id: u64,
        class: TrafficClass,
        priority: bool,
        route: ResolvedRouteV2,
        overlay_hop_limit: u8,
        records: Vec<TrainRecord>,
        trace_probe: Option<TraceProbeTag>,
        ingress_permits: Vec<OwnedSemaphorePermit>,
    },
    Forward {
        flow_id: u64,
        cells: Vec<Bytes>,
    },
    Control(TxControl),
}

#[derive(Debug)]
struct MeshDatagramV2 {
    incoming: AdjacencyIdV2,
    datagrams: Vec<Bytes>,
}

#[derive(Debug)]
struct MeshControlRecordV2 {
    incoming: AdjacencyIdV2,
    bytes: Bytes,
}

#[derive(Debug)]
struct MeshRepairDeliveryV2 {
    incoming: AdjacencyIdV2,
    response: RepairResponseV2,
}

#[derive(Debug)]
struct MeshPathMtuEventV2 {
    incoming: AdjacencyIdV2,
    oam: OamPathMtuExceededV2,
}

#[derive(Debug)]
struct MeshRxMetricsV2 {
    tun: Arc<RuntimeMetrics>,
    adjacencies: HashMap<AdjacencyIdV2, Arc<RuntimeMetrics>>,
}

#[derive(Debug)]
struct MeshFlowStateV2 {
    classifier: FlowClassifier,
    last_seen: Duration,
    lease: crate::protocol::v2::routing::FlowRouteLeaseV2,
    effective_route: ResolvedRouteV2,
    path_mtu_generation: u64,
}

#[derive(Debug, Default)]
struct RoutePmtuConstraintsV2 {
    values: ArcSwap<HashMap<(u32, u32), u16>>,
    generation: AtomicU64,
}

impl RoutePmtuConstraintsV2 {
    fn constrain(&self, route_epoch: u32, route_label: RouteLabelV2, maximum: u16) {
        let current = self.values.load_full();
        let key = (route_epoch, route_label.0);
        if current
            .get(&key)
            .is_some_and(|existing| *existing <= maximum)
        {
            return;
        }
        let mut next = if current.len() >= MAX_PATH_MTU_CONSTRAINTS {
            HashMap::default()
        } else {
            (*current).clone()
        };
        next.entry(key)
            .and_modify(|existing| *existing = (*existing).min(maximum))
            .or_insert(maximum);
        self.values.store(Arc::new(next));
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn apply(&self, mut route: ResolvedRouteV2) -> ResolvedRouteV2 {
        if let Some(maximum) = self
            .values
            .load()
            .get(&(route.route_epoch, route.route_label.0))
        {
            route.maximum_datagram_size = route.maximum_datagram_size.min(*maximum);
        }
        route
    }
}

pub(super) async fn run_mesh(
    config: V2RuntimeConfig,
    endpoint: Endpoint,
    derp_transport: Option<Arc<DerpTransport>>,
    secret_key: SecretKey,
    local_id: EndpointId,
    shutdown: &mut ShutdownFuture,
    runtime_state: Arc<V2RuntimeState>,
) -> Result<()> {
    ensure!(
        config
            .mesh_peers
            .iter()
            .all(|peer| peer.endpoint_id != local_id),
        "V2 mesh peer list contains the local EndpointId"
    );
    let adjacencies = tokio::select! {
        // Mesh establishment includes dial/accept and SessionHello for every
        // adjacency, so it too must remain cancellable before tasks exist.
        biased;
        signal = shutdown.as_mut() => {
            signal?;
            info!("received V2 mesh shutdown signal during adjacency establishment");
            endpoint.close().await;
            return Ok(());
        }
        result = establish_mesh_adjacencies(&endpoint, &config, local_id, derp_transport) => result?,
    };
    ensure!(!adjacencies.is_empty(), "V2 mesh has no active adjacency");
    for adjacency in &adjacencies {
        runtime_state.mark_connected(&adjacency.connection);
    }
    info!(
        peers = adjacencies.len(),
        "V2 authenticated mesh adjacencies active"
    );

    let (local_overlay_v4, local_overlay_v6) = local_overlay_addresses(&config, local_id);
    let tunnel = OverlayTunnel::create(config.tun_name.clone(), config.tun_mtu)?;
    let (route_policy, _kernel_route_guard) =
        configure_mesh_tunnel(&config, local_overlay_v4, local_overlay_v6)?;
    runtime_state.publish_routes(config.routes.iter().copied());
    reconcile_v2_nat(
        &config.tun_name,
        &config.advertised_routes,
        config.subnet_nat,
    )?;
    info!(
        interface = %config.tun_name,
        local_overlay_v4 = %local_overlay_v4,
        local_overlay_v6 = %local_overlay_v6,
        queues = tunnel.queue_count(),
        "V2 mesh TUN configured"
    );

    let initial = DataplaneSnapshotV2::empty(1, *local_id.as_bytes())?;
    let snapshots = Arc::new(DataplaneSnapshotStoreV2::new(initial));
    let path_mtu_constraints = Arc::new(RoutePmtuConstraintsV2::default());
    let (tun_priority_sender, tun_priority_receiver) = mpsc::channel(TUN_PRIORITY_INPUT_SLOTS);
    // Merge kernel RSS queues before route/class admission. Sharding before
    // the single adjacency scheduler lets a busy hash bucket monopolize the
    // bounded command channel and makes equal flows receive unequal service.
    let (tun_regular_sender, tun_regular_receiver) = mpsc::channel(TUN_INPUT_SLOTS);
    let (datagram_sender, datagram_receiver) = mpsc::channel(2048);
    let (control_record_sender, control_record_receiver) = mpsc::channel(512);
    let (repair_sender, repair_receiver) = mpsc::channel(256);
    let (path_mtu_sender, path_mtu_receiver) = mpsc::channel(64);
    let (route_sender, route_receiver) = mpsc::channel(16);
    let mut commands = HashMap::<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>::default();
    let mut priority_commands = HashMap::<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>::default();
    let mut adjacency_metrics = HashMap::<AdjacencyIdV2, Arc<RuntimeMetrics>>::default();
    let mut tasks = JoinSet::new();
    let shutting_down = Arc::new(AtomicBool::new(false));
    spawn_named_mesh_task(
        &mut tasks,
        "process CPU sampler",
        shutting_down.clone(),
        cpu_sampler_loop(runtime_state.clone()),
    );

    let tun_metrics = runtime_state.tun_ingress_metrics.clone();
    // This shared budget only merges one bounded GSO burst from the RSS
    // readers. Route dispatch still feeds each adjacency through the 512-KiB
    // scheduler high-water mark in `mesh_tx_loop`.
    let tun_regular_budget = Arc::new(Semaphore::new(TUN_REGULAR_INPUT_BYTES));
    for (queue, device) in tunnel.devices.iter().enumerate() {
        spawn_named_mesh_task(
            &mut tasks,
            format!("TUN reader queue {queue}"),
            shutting_down.clone(),
            prioritized_tun_reader(
                device.clone(),
                tun_regular_sender.clone(),
                tun_priority_sender.clone(),
                tun_regular_budget.clone(),
                tun_metrics.clone(),
                tunnel.mtu,
            ),
        );
    }
    drop(tun_regular_sender);
    drop(tun_priority_sender);

    for adjacency in &adjacencies {
        let (command_sender, command_receiver) = mpsc::channel(4);
        let (priority_command_sender, priority_command_receiver) =
            mpsc::channel(TUN_PRIORITY_INPUT_SLOTS);
        let (tune_sender, tune_receiver) = watch::channel(None::<TuneDecisionV2>);
        commands.insert(adjacency.id, command_sender);
        priority_commands.insert(adjacency.id, priority_command_sender);
        let metrics = Arc::new(RuntimeMetrics::default());
        runtime_state.attach_metrics(adjacency.remote_id, metrics.clone());
        adjacency_metrics.insert(adjacency.id, metrics.clone());
        spawn_named_mesh_task(
            &mut tasks,
            format!("adjacency {} TX", adjacency.id.0),
            shutting_down.clone(),
            mesh_tx_loop(
                adjacency.clone(),
                command_receiver,
                priority_command_receiver,
                tune_receiver,
                metrics.clone(),
                path_mtu_sender.clone(),
                local_id,
                snapshots.clone(),
                runtime_state.clone(),
            ),
        );
        spawn_named_mesh_task(
            &mut tasks,
            format!("adjacency {} DATAGRAM reader", adjacency.id.0),
            shutting_down.clone(),
            mesh_datagram_reader(adjacency.clone(), datagram_sender.clone()),
        );
        spawn_named_mesh_task(
            &mut tasks,
            format!("adjacency {} control reader", adjacency.id.0),
            shutting_down.clone(),
            mesh_control_reader(adjacency.clone(), control_record_sender.clone()),
        );
        spawn_named_mesh_task(
            &mut tasks,
            format!("adjacency {} tuner", adjacency.id.0),
            shutting_down.clone(),
            tuner_loop(
                adjacency.connection.clone(),
                metrics,
                tune_sender,
                runtime_state.clone(),
                ticket_partition_label(
                    &config.network_id,
                    config.cover_profile_id,
                    QUIC_WIRE_VERSION,
                ),
            ),
        );
    }
    drop(datagram_sender);
    drop(control_record_sender);
    drop(path_mtu_sender);

    let mut direct_addresses = adjacencies
        .iter()
        .flat_map(|adjacency| selected_direct_addresses(&adjacency.connection, config.bind.port()))
        .collect::<Vec<_>>();
    if config.bind.port() != 0 && !config.bind.ip().is_unspecified() {
        direct_addresses.push(config.bind);
    }
    direct_addresses.sort_unstable();
    direct_addresses.dedup();
    direct_addresses.truncate(crate::protocol::v2::presence::MAX_DIRECT_ADDRESSES);

    let now = unix_secs(SystemTime::now())?;
    let local_presence = SignedPresenceV2::sign(
        PresenceBodyV2 {
            owner: local_id,
            sequence: 1,
            issued_unix_secs: now,
            expires_unix_secs: now.saturating_add(180),
            direct_addresses,
            node_addresses: vec![
                IpNet::from(std::net::IpAddr::V4(local_overlay_v4)),
                IpNet::from(std::net::IpAddr::V6(local_overlay_v6)),
            ],
            prefixes: config.advertised_routes.clone(),
            links: adjacencies
                .iter()
                .map(|adjacency| PresenceLinkV2 {
                    peer: adjacency.remote_id,
                    cost: selected_path_cost(&adjacency.connection),
                    healthy: true,
                    // QUIC frequently exposes its conservative 1,162-byte
                    // floor for a few milliseconds after SessionHello. Start
                    // at the authenticated negotiated ceiling; a real PMTU
                    // reduction is fed back immediately by reliable OAM and
                    // later confirmed by Presence refresh.
                    maximum_datagram_size: adjacency.negotiated.limits.max_datagram_size,
                })
                .collect(),
            transit_enabled: config.transit_enabled,
        },
        &secret_key,
        &config.network_id,
    )?;

    spawn_named_mesh_task(
        &mut tasks,
        "regular TUN dispatcher",
        shutting_down.clone(),
        mesh_tun_loop(
            tun_regular_receiver,
            snapshots.clone(),
            commands.clone(),
            priority_commands.clone(),
            path_mtu_constraints.clone(),
            adjacency_metrics.clone(),
            false,
        ),
    );
    spawn_named_mesh_task(
        &mut tasks,
        "priority TUN dispatcher",
        shutting_down.clone(),
        mesh_tun_loop(
            tun_priority_receiver,
            snapshots.clone(),
            commands.clone(),
            priority_commands,
            path_mtu_constraints.clone(),
            adjacency_metrics.clone(),
            true,
        ),
    );
    spawn_named_mesh_task(
        &mut tasks,
        "DATAGRAM dispatcher",
        shutting_down.clone(),
        mesh_datagram_loop(
            adjacencies.clone(),
            datagram_receiver,
            repair_receiver,
            tunnel.writer(),
            snapshots.clone(),
            commands.clone(),
            MeshRxMetricsV2 {
                tun: tun_metrics,
                adjacencies: adjacency_metrics.clone(),
            },
        ),
    );
    spawn_named_mesh_task(
        &mut tasks,
        "control manager",
        shutting_down.clone(),
        mesh_control_loop(
            config.network_id.clone(),
            local_id,
            local_presence,
            secret_key,
            adjacencies.clone(),
            control_record_receiver,
            path_mtu_receiver,
            repair_sender,
            route_sender.clone(),
            snapshots,
            commands,
            path_mtu_constraints,
            config.allow_default_routes,
            config.bind,
            adjacency_metrics,
            runtime_state.clone(),
            config.mesh_peers.len().saturating_add(1),
        ),
    );
    spawn_named_mesh_task(
        &mut tasks,
        "route manager",
        shutting_down.clone(),
        route_loop(
            route_policy,
            config.routes.clone(),
            route_receiver,
            runtime_state,
        ),
    );

    let outcome = tokio::select! {
        signal = shutdown.as_mut() => {
            signal?;
            shutting_down.store(true, Ordering::Release);
            info!("received V2 mesh shutdown signal");
            Ok(())
        },
        result = tasks.join_next() => match result {
            Some(Ok(result)) => result.context("V2 mesh task stopped"),
            Some(Err(error)) => Err(error).context("V2 mesh task panicked"),
            None => bail!("V2 mesh has no active tasks"),
        },
    };
    for adjacency in &adjacencies {
        adjacency.connection.close(0_u8.into(), b"V2 mesh shutdown");
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    endpoint.close().await;
    outcome
}

fn spawn_named_mesh_task<F>(
    tasks: &mut JoinSet<Result<()>>,
    name: impl Into<String>,
    shutting_down: Arc<AtomicBool>,
    future: F,
) where
    F: Future<Output = Result<()>> + Send + 'static,
{
    let name = name.into();
    tasks.spawn(async move {
        let result = future.await;
        if !shutting_down.load(Ordering::Acquire) {
            match &result {
                Ok(()) => warn!(task = %name, "V2 mesh task returned unexpectedly"),
                Err(error) => {
                    warn!(task = %name, error = %format_args!("{error:#}"), "V2 mesh task failed")
                }
            }
        }
        result.with_context(|| format!("V2 mesh {name} stopped"))
    });
}

#[allow(clippy::too_many_arguments)]
async fn mesh_tx_loop(
    adjacency: PeerSessionV2,
    mut commands: mpsc::Receiver<MeshTxCommandV2>,
    mut priority_commands: mpsc::Receiver<MeshTxCommandV2>,
    mut tuning: watch::Receiver<Option<TuneDecisionV2>>,
    metrics: Arc<RuntimeMetrics>,
    path_mtu_events: mpsc::Sender<MeshPathMtuEventV2>,
    local_id: EndpointId,
    snapshots: Arc<DataplaneSnapshotStoreV2>,
    runtime_state: Arc<V2RuntimeState>,
) -> Result<()> {
    let mut tx = V2Tx::new_for_adjacency(
        adjacency.connection,
        adjacency.negotiated,
        SchedulerLimits::default(),
        adjacency.id,
    )?;
    let mut applied_tuning = None::<TuneDecisionV2>;
    let mut cover_shaper = CoverShaperV2::default();
    let mut priority_send = PrioritySendArbiterV2::default();
    loop {
        enum Event {
            Command {
                command: Option<MeshTxCommandV2>,
                priority_admission: bool,
            },
            Tuned,
            Sent(Result<Option<crate::protocol::v2::dataplane::SendProgress>>),
        }
        let event = if tx.has_pending()
            && admission_saturated(tx.depth(), tx_admission_high_water(&tx))
        {
            if ingress_ready_order(true, priority_send.next())
                == IngressReadyOrderV2::PriorityThenSend
            {
                tokio::select! {
                    biased;
                    changed = tuning.changed() => {
                        changed.context("V2 mesh tuner stopped")?;
                        Event::Tuned
                    }
                    command = priority_commands.recv() => Event::Command { command, priority_admission: true },
                    sent = tx.send_next() => Event::Sent(sent),
                }
            } else {
                tokio::select! {
                    biased;
                    changed = tuning.changed() => {
                        changed.context("V2 mesh tuner stopped")?;
                        Event::Tuned
                    }
                    sent = tx.send_next() => Event::Sent(sent),
                    command = priority_commands.recv() => Event::Command { command, priority_admission: true },
                }
            }
        } else if tx.has_pending() {
            if ingress_ready_order(false, priority_send.next())
                == IngressReadyOrderV2::SendThenPriorityThenRegular
            {
                tokio::select! {
                    biased;
                    changed = tuning.changed() => {
                        changed.context("V2 mesh tuner stopped")?;
                        Event::Tuned
                    }
                    sent = tx.send_next() => Event::Sent(sent),
                    command = priority_commands.recv() => Event::Command { command, priority_admission: true },
                    command = commands.recv() => Event::Command { command, priority_admission: false },
                }
            } else {
                tokio::select! {
                    biased;
                    changed = tuning.changed() => {
                        changed.context("V2 mesh tuner stopped")?;
                        Event::Tuned
                    }
                    command = priority_commands.recv() => Event::Command { command, priority_admission: true },
                    sent = tx.send_next() => Event::Sent(sent),
                    command = commands.recv() => Event::Command { command, priority_admission: false },
                }
            }
        } else {
            tokio::select! {
                biased;
                command = priority_commands.recv() => Event::Command { command, priority_admission: true },
                changed = tuning.changed() => {
                    changed.context("V2 mesh tuner stopped")?;
                    Event::Tuned
                }
                command = commands.recv() => Event::Command { command, priority_admission: false },
            }
        };
        match event {
            Event::Command { command: None, .. } => {
                bail!("V2 mesh adjacency command channel stopped")
            }
            Event::Command {
                command: Some(command),
                priority_admission,
            } => {
                if priority_admission {
                    priority_send.admitted_priority();
                }
                match command {
                    MeshTxCommandV2::Records {
                        flow_id,
                        class,
                        priority,
                        route,
                        overlay_hop_limit,
                        records,
                        trace_probe,
                        ingress_permits: _ingress_permits,
                    } => {
                        let admitted = tx.enqueue_routed_records_auto_with_priority(
                            flow_id,
                            class,
                            route,
                            overlay_hop_limit,
                            records,
                            priority,
                        )?;
                        ensure!(!admitted.is_empty(), "V2 mesh rejected PacketTrain");
                        if let Some(trace_probe) = trace_probe {
                            // A normal trace hop is one 1 KiB record and one train. If
                            // a crafted/GSO group spans trains, correlate every train;
                            // the first authenticated OAM response retires the group.
                            for train_id in admitted {
                                runtime_state.register_trace_train(route, train_id, trace_probe);
                            }
                        }
                    }
                    MeshTxCommandV2::Forward { flow_id, cells } => {
                        match tx.admit_forwarded_cells(flow_id, cells)? {
                            ForwardAdmissionV2::Admitted => {}
                            ForwardAdmissionV2::QueueFull => {
                                warn!(
                                    adjacency = adjacency.id.0,
                                    "dropped V2 transit batch at queue limit"
                                );
                            }
                            ForwardAdmissionV2::PathMtuExceeded {
                                header,
                                observed_datagram_size,
                                maximum_datagram_size,
                            } => {
                                let observed_datagram_size = u16::try_from(observed_datagram_size)
                                    .context("V2 forwarded Cell exceeds wire range")?;
                                let maximum_datagram_size = u16::try_from(maximum_datagram_size)
                                    .context("V2 live adjacency PMTU exceeds wire range")?;
                                let incoming = header_incoming_adjacency(
                                    header.route_label,
                                    header.session_epoch,
                                    adjacency.id,
                                    &snapshots,
                                )?;
                                path_mtu_events
                                    .send(MeshPathMtuEventV2 {
                                        incoming,
                                        oam: OamPathMtuExceededV2 {
                                            snapshot_generation: snapshots.load().generation(),
                                            route_epoch: header.session_epoch,
                                            route_label: RouteLabelV2::new(header.route_label)?,
                                            train_id: header.train_id,
                                            cell_sequence: header.cell_sequence,
                                            observed_datagram_size,
                                            maximum_datagram_size,
                                            incoming,
                                            reporter: *local_id.as_bytes(),
                                        },
                                    })
                                    .await
                                    .context("V2 mesh path-MTU event manager stopped")?;
                            }
                        }
                    }
                    MeshTxCommandV2::Control(TxControl::Send(record)) => {
                        metrics.observe_control_tx(&record);
                        ensure!(tx.enqueue_control(record)?, "V2 mesh control queue is full");
                    }
                    MeshTxCommandV2::Control(TxControl::Respond(request)) => {
                        let response = tx.repair_response(&request).encode()?;
                        metrics.observe_control_tx(&response);
                        ensure!(
                            tx.enqueue_control(response)?,
                            "V2 mesh control queue is full"
                        );
                    }
                }
            }
            Event::Tuned => {
                if let Some(decision) = *tuning.borrow_and_update()
                    && applied_tuning.is_none_or(|current| {
                        effective_tx_tuning(current) != effective_tx_tuning(decision)
                    })
                {
                    tx.apply_tuning(decision)?;
                    cover_shaper.update(decision);
                    info!(
                        adjacency = adjacency.id.0,
                        reason = ?decision.reason,
                        path_epoch = decision.path_epoch,
                        train_bytes = decision.train_target_bytes,
                        quantum_cells = decision.bulk_quantum_cells,
                        fec = ?decision.fec,
                        repair_cache_bytes = decision.repair_cache_bytes,
                        send_buffer_bytes = decision.send_buffer_bytes,
                        datagram_admission_bytes = tx.datagram_send_buffer_limit(),
                        receive_buffer_bytes = decision.receive_buffer_bytes,
                        receive_batch = decision.receive_batch,
                        cover_profile = ?decision.cover_profile,
                        cover_overhead_per_mille = decision.cover_overhead_per_mille,
                        cover_padding_bytes_per_second = decision.cover_padding_bytes_per_second,
                        "applied automatic V2 mesh tuning decision"
                    );
                    applied_tuning = Some(decision);
                }
            }
            Event::Sent(result) => {
                priority_send.completed_send();
                if let Some(progress) = result? {
                    metrics.observe_send(progress);
                    let sent_real = progress.class.is_some();
                    if sent_real {
                        metrics
                            .real_tx_bytes
                            .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    }
                    metrics
                        .cover_tx_bytes
                        .fetch_add(progress.cover_padding_bytes as u64, Ordering::Relaxed);
                    metrics
                        .pmtu_drop_bytes
                        .fetch_add(progress.dropped_bytes as u64, Ordering::Relaxed);
                    metrics
                        .pmtu_drop_datagrams
                        .fetch_add(progress.dropped_datagrams as u64, Ordering::Relaxed);
                    if sent_real && !tx.has_pending() {
                        let _ = cover_shaper.enqueue_after_real(&mut tx)?;
                    }
                }
            }
        }
        let depth = tx.depth();
        metrics.train_queue_bytes.store(
            (depth.bulk_bytes + depth.latency_bytes) as u64,
            Ordering::Relaxed,
        );
        metrics
            .latency_queue_bytes
            .store(depth.latency_bytes as u64, Ordering::Relaxed);
    }
}

fn header_incoming_adjacency(
    route_label: u32,
    route_epoch: u32,
    outgoing: AdjacencyIdV2,
    snapshots: &DataplaneSnapshotStoreV2,
) -> Result<AdjacencyIdV2> {
    let route_label = RouteLabelV2::new(route_label)?;
    match snapshots.label_action(route_epoch, route_label) {
        Some(LabelActionV2::Forward {
            expected_ingress,
            next_hop,
        }) if next_hop == outgoing => Ok(expected_ingress),
        _ => bail!("V2 path-MTU event has no reverse label action"),
    }
}

async fn mesh_datagram_reader(
    adjacency: PeerSessionV2,
    sender: mpsc::Sender<MeshDatagramV2>,
) -> Result<()> {
    // This is a non-blocking drain of DATAGRAMs that have already arrived;
    // using the negotiated hard batch bound cannot add coalescing latency and
    // strictly reduces channel wakeups compared with a feedback downshift.
    let receive_batch = AutoTuneBoundsV2::default().maximum_receive_batch;
    loop {
        let datagrams = adjacency
            .connection
            .read_datagram_batch(receive_batch)
            .await
            .context("receiving V2 mesh DATAGRAM batch")?;
        sender
            .send(MeshDatagramV2 {
                incoming: adjacency.id,
                datagrams,
            })
            .await
            .context("V2 mesh dispatcher stopped")?;
    }
}

async fn mesh_control_reader(
    adjacency: PeerSessionV2,
    sender: mpsc::Sender<MeshControlRecordV2>,
) -> Result<()> {
    let mut receiver = V2ControlRx::new(adjacency.connection, adjacency.negotiated);
    loop {
        sender
            .send(MeshControlRecordV2 {
                incoming: adjacency.id,
                bytes: receiver.receive().await?,
            })
            .await
            .context("V2 mesh control manager stopped")?;
    }
}

async fn mesh_tun_loop(
    mut input: mpsc::Receiver<TunIngressRecordV2>,
    snapshots: Arc<DataplaneSnapshotStoreV2>,
    commands: HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    priority_commands: HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    path_mtu_constraints: Arc<RoutePmtuConstraintsV2>,
    metrics: HashMap<AdjacencyIdV2, Arc<RuntimeMetrics>>,
    priority: bool,
) -> Result<()> {
    let started = Instant::now();
    let mut flows = HashMap::<FlowKey, MeshFlowStateV2>::default();
    let mut pending = VecDeque::<TunIngressRecordV2>::new();
    loop {
        if pending.is_empty() {
            pending.push_back(input.recv().await.context(if priority {
                "all V2 mesh priority TUN readers stopped"
            } else {
                "all V2 mesh TUN readers stopped"
            })?);
            while pending.len() < AutoTuneBoundsV2::default().maximum_receive_batch {
                match input.try_recv() {
                    Ok(record) => pending.push_back(record),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
        }
        let records = drain_tun_ingress_batch(
            &mut pending,
            AutoTuneBoundsV2::default().maximum_receive_batch,
            if priority {
                TX_LATENCY_ADMISSION_HIGH_WATER_BYTES
            } else {
                TX_ADMISSION_BATCH_BYTES
            },
        );
        enqueue_mesh_tun_batch(
            records,
            &mut flows,
            started.elapsed(),
            &snapshots,
            &commands,
            &priority_commands,
            &path_mtu_constraints,
            &metrics,
            priority,
        )
        .await?;
        if flows.len() > MAX_CLASSIFIERS {
            let now = started.elapsed();
            flows.retain(|_, state| now.saturating_sub(state.last_seen) < CLASSIFIER_IDLE);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_mesh_tun_batch(
    batch: Vec<TunIngressRecordV2>,
    flows: &mut HashMap<FlowKey, MeshFlowStateV2>,
    now: Duration,
    snapshots: &DataplaneSnapshotStoreV2,
    commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    priority_commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    path_mtu_constraints: &RoutePmtuConstraintsV2,
    metrics: &HashMap<AdjacencyIdV2, Arc<RuntimeMetrics>>,
    priority: bool,
) -> Result<()> {
    #[derive(Default)]
    struct Group {
        records: Vec<(Bytes, Bytes)>,
        trace_probe: Option<TraceProbeTag>,
        permits: Vec<OwnedSemaphorePermit>,
    }

    let mut grouped = HashMap::<(ResolvedRouteV2, u64, TrafficClass, u8), Group>::default();
    let mut ingress = HashMap::<AdjacencyIdV2, TunIngressBatchV2>::default();
    for record in batch {
        let TunIngressRecordV2 {
            bytes: raw,
            info,
            gso: reader_gso,
            _permit: permit,
        } = record;
        let packet = &raw[VIRTIO_NET_HDR_LEN..];
        let packet_len = packet.len();
        let trace_probe = (info.protocol == 17
            && info.destination_port == Some(crate::trace::TRACE_PORT))
        .then(|| v2_trace_probe_tag(packet))
        .flatten();
        let key = FlowKey::from(info);
        if info.destination.is_multicast() {
            continue;
        }
        let id = flow_id(key);
        let hop_limit = ip_hop_limit_validated(packet);
        if hop_limit == 0 {
            continue;
        }
        let snapshot = snapshots.load();
        if let Some(state) = flows.get_mut(&key)
            && state.lease.snapshot_generation() != snapshot.generation()
        {
            if let Err(error) = state.lease.refresh(snapshot.clone()) {
                warn!(%error, destination = %info.destination, "V2 mesh flow route disappeared");
                flows.remove(&key);
                continue;
            }
            state.effective_route = path_mtu_constraints.apply(state.lease.route());
            state.path_mtu_generation = path_mtu_constraints.generation();
        }
        if let Entry::Vacant(entry) = flows.entry(key) {
            let lease = match crate::protocol::v2::routing::FlowRouteLeaseV2::resolve(
                snapshot,
                info.destination,
            ) {
                Ok(lease) => lease,
                Err(error) => {
                    warn!(%error, destination = %info.destination, "dropped unroutable V2 mesh packet");
                    continue;
                }
            };
            entry.insert(MeshFlowStateV2 {
                classifier: FlowClassifier::new(ClassifierConfig::default(), now),
                last_seen: now,
                effective_route: path_mtu_constraints.apply(lease.route()),
                path_mtu_generation: path_mtu_constraints.generation(),
                lease,
            });
        }
        let state = flows.get_mut(&key).expect("V2 mesh flow was inserted");
        let path_mtu_generation = path_mtu_constraints.generation();
        if state.path_mtu_generation != path_mtu_generation {
            state.effective_route = path_mtu_constraints.apply(state.lease.route());
            state.path_mtu_generation = path_mtu_generation;
        }
        state.last_seen = now;
        let class = state
            .classifier
            .observe(now, packet_len, 0, info.latency_protected);
        let route = state.effective_route;
        let (metadata, data, mut gso) = match encode_train_record_observed(raw) {
            Ok(record) => record,
            Err(error) => {
                warn!(%error, "dropped invalid V2 mesh GSO metadata");
                continue;
            }
        };
        gso.input_bytes = gso.input_bytes.saturating_add(reader_gso.input_bytes);
        gso.preserved_bytes = gso
            .preserved_bytes
            .saturating_add(reader_gso.preserved_bytes);
        gso.fallback_splits = gso
            .fallback_splits
            .saturating_add(reader_gso.fallback_splits);
        if !commands.contains_key(&route.adjacency) {
            warn!(
                adjacency = route.adjacency.0,
                "V2 mesh route has no live writer"
            );
            continue;
        }
        ingress
            .entry(route.adjacency)
            .or_default()
            .observe(packet_len, gso);
        let group = grouped.entry((route, id, class, hop_limit)).or_default();
        group.records.push((metadata, data));
        group.trace_probe = group.trace_probe.or(trace_probe);
        if let Some(permit) = permit {
            group.permits.push(permit);
        }
    }
    for ((route, flow_id, class, overlay_hop_limit), group) in grouped {
        let records = group
            .records
            .into_iter()
            .enumerate()
            .map(|(index, (metadata, data))| {
                Ok(TrainRecord {
                    record_id: u16::try_from(index + 1)
                        .context("V2 mesh TUN batch has too many records")?,
                    metadata,
                    data,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let sender = if priority {
            &priority_commands[&route.adjacency]
        } else {
            &commands[&route.adjacency]
        };
        sender
            .send(MeshTxCommandV2::Records {
                flow_id,
                class,
                priority,
                route,
                overlay_hop_limit,
                records,
                trace_probe: group.trace_probe,
                ingress_permits: group.permits,
            })
            .await
            .context("V2 mesh adjacency writer stopped")?;
    }
    for (adjacency, observation) in ingress {
        metrics[&adjacency].observe_tun_ingress_batch(observation);
    }
    Ok(())
}

async fn mesh_datagram_loop(
    adjacencies: Vec<PeerSessionV2>,
    mut datagrams: mpsc::Receiver<MeshDatagramV2>,
    mut repairs: mpsc::Receiver<MeshRepairDeliveryV2>,
    mut writer: crate::tunnel::OverlayTunnelWriter,
    snapshots: Arc<DataplaneSnapshotStoreV2>,
    commands: HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    metrics: MeshRxMetricsV2,
) -> Result<()> {
    let mut receivers = HashMap::<AdjacencyIdV2, V2Rx>::default();
    for adjacency in adjacencies {
        receivers.insert(
            adjacency.id,
            V2Rx::new(
                adjacency.connection,
                adjacency.negotiated,
                minimum_receive_buffer_bytes(),
            )?,
        );
    }
    let mut repair_tick = tokio::time::interval(Duration::from_millis(10));
    repair_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_tick = tokio::time::interval(Duration::from_secs(1));
    feedback_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_sequence = 0_u64;
    loop {
        tokio::select! {
            datagram = datagrams.recv() => {
                let batch = datagram.context("all V2 mesh DATAGRAM readers stopped")?;
                let receiver = receivers
                    .get_mut(&batch.incoming)
                    .context("V2 mesh DATAGRAM has no receiver")?;
                let adjacency_metrics = metrics
                    .adjacencies
                    .get(&batch.incoming)
                    .context("V2 mesh DATAGRAM has no adjacency metrics")?;
                let evicted = apply_receive_buffer_target(receiver, adjacency_metrics)?;
                if evicted != 0 {
                    warn!(
                        incoming = batch.incoming.0,
                        evicted,
                        receive_buffer_bytes = receiver.maximum_buffered_bytes(),
                        "evicted stale V2 mesh RX state while shrinking automatic budget"
                    );
                }
                let mut forwarded = HashMap::<
                    (AdjacencyIdV2, TrafficClass, u32, u32, u64),
                    Vec<Bytes>,
                >::default();
                let mut local = ReassemblyOutput::default();
                for bytes in batch.datagrams {
                    if CoverPaddingV2::is_record(&bytes) {
                        let receiver = receivers
                            .get_mut(&batch.incoming)
                            .context("V2 mesh cover padding has no receiver")?;
                        let length = bytes.len();
                        if let Err(error) = receiver.accept_datagram(bytes) {
                            let (errors, report) =
                                adjacency_metrics.record_protocol_datagram_error();
                            if report {
                                warn!(
                                    incoming = batch.incoming.0,
                                    errors,
                                    stage = "cover",
                                    %error,
                                    "dropped malformed V2 mesh DATAGRAM; further errors are exponentially sampled"
                                );
                            }
                            continue;
                        }
                        metrics
                            .adjacencies
                            .get(&batch.incoming)
                            .context("V2 mesh cover padding has no adjacency metrics")?
                            .cover_rx_bytes
                            .fetch_add(length as u64, Ordering::Relaxed);
                        continue;
                    }
                    let disposition = match snapshots.dispatch_cell(batch.incoming, bytes) {
                        Ok(disposition) => disposition,
                        Err(error) => {
                            let (errors, report) =
                                adjacency_metrics.record_protocol_datagram_error();
                            if report {
                                warn!(
                                    incoming = batch.incoming.0,
                                    errors,
                                    stage = "cell-route",
                                    %error,
                                    "dropped malformed V2 mesh DATAGRAM; further errors are exponentially sampled"
                                );
                            }
                            continue;
                        }
                    };
                    match disposition {
                        TransitDispositionV2::Local { header, cell } => {
                            let receiver = receivers
                                .get_mut(&batch.incoming)
                                .context("V2 mesh local Cell has no receiver")?;
                            if let Err(error) = receiver.activate_route_epoch(header.session_epoch) {
                                let (errors, report) =
                                    adjacency_metrics.record_protocol_datagram_error();
                                if report {
                                    warn!(
                                        incoming = batch.incoming.0,
                                        errors,
                                        stage = "route-epoch",
                                        %error,
                                        "dropped invalid V2 mesh DATAGRAM; further errors are exponentially sampled"
                                    );
                                }
                                continue;
                            }
                            let output = match receiver.accept_routed_datagram(cell, header) {
                                Ok(output) => output,
                                Err(error) => {
                                    let (errors, report) =
                                        adjacency_metrics.record_protocol_datagram_error();
                                    if report {
                                        warn!(
                                            incoming = batch.incoming.0,
                                            errors,
                                            stage = "cell-payload",
                                            %error,
                                            "dropped malformed V2 mesh DATAGRAM; further errors are exponentially sampled"
                                        );
                                    }
                                    continue;
                                }
                            };
                            metrics.adjacencies[&batch.incoming].observe_receive(&output);
                            metrics.adjacencies[&batch.incoming]
                                .observe_local_delivery(&output);
                            local.merge(output);
                        }
                        TransitDispositionV2::Forward { next_hop, cell } => {
                            forwarded
                                .entry((
                                    next_hop,
                                    cell.header.class,
                                    cell.header.session_epoch,
                                    cell.header.route_label,
                                    cell.header.train_id,
                                ))
                                .or_default()
                                .push(cell.bytes);
                        }
                        TransitDispositionV2::TtlExpired(oam) => {
                            let sender = commands
                                .get(&oam.incoming)
                                .context("V2 mesh TTL OAM reverse adjacency is disconnected")?;
                            sender.send(MeshTxCommandV2::Control(TxControl::Send(oam.encode()?)))
                                .await.context("V2 mesh OAM writer stopped")?;
                        }
                        TransitDispositionV2::Drop(reason) => {
                            let (drops, report) = adjacency_metrics.record_route_gate_drop();
                            if report {
                                warn!(
                                    ?reason,
                                    incoming = batch.incoming.0,
                                    drops,
                                    "dropped V2 mesh Cell at route-label gate; further drops are exponentially sampled"
                                );
                            }
                        }
                    }
                }
                for ((next_hop, _class, _epoch, _label, train_id), cells) in forwarded {
                    let sender = commands
                        .get(&next_hop)
                        .context("V2 mesh transit next hop is disconnected")?;
                    sender.send(MeshTxCommandV2::Forward {
                        flow_id: train_id.max(1),
                        cells,
                    }).await.context("V2 mesh transit writer stopped")?;
                }
                write_reassembled(&mut writer, &metrics.tun, local).await?;
            }
            repair = repairs.recv() => {
                let repair = repair.context("V2 mesh control manager stopped")?;
                let receiver = receivers
                    .get_mut(&repair.incoming)
                    .context("V2 mesh Repair response has no receiver")?;
                let adjacency_metrics = metrics
                    .adjacencies
                    .get(&repair.incoming)
                    .context("V2 mesh Repair response has no adjacency metrics")?;
                let evicted = apply_receive_buffer_target(receiver, adjacency_metrics)?;
                if evicted != 0 {
                    warn!(
                        incoming = repair.incoming.0,
                        evicted,
                        receive_buffer_bytes = receiver.maximum_buffered_bytes(),
                        "evicted stale V2 mesh RX state while shrinking automatic budget"
                    );
                }
                let request_id = repair.response.request_id;
                let route_epoch = repair.response.key.session_epoch;
                match receiver.accept_repair_response_at(repair.response, Instant::now())? {
                    Some((output, observation)) => {
                        metrics.adjacencies[&repair.incoming]
                            .observe_repair_response(observation);
                        metrics.adjacencies[&repair.incoming].observe_receive(&output);
                        metrics.adjacencies[&repair.incoming].observe_local_delivery(&output);
                        write_reassembled(&mut writer, &metrics.tun, output).await?;
                    }
                    None => {
                        let (stale, report) = increment_sampled_counter(
                            &metrics.adjacencies[&repair.incoming].repair_stale_responses,
                        );
                        if report {
                            warn!(
                                incoming = repair.incoming.0,
                                request_id,
                                route_epoch,
                                stale,
                                "ignored unmatched or expired V2 mesh Repair response; further events are exponentially sampled"
                            );
                        }
                    }
                }
            }
            _ = repair_tick.tick() => {
                let now = Instant::now();
                for (&incoming, receiver) in &mut receivers {
                    let repair_batch = receiver.repair_requests_bounded(
                        now,
                        adaptive_repair_minimum_age(&metrics.adjacencies[&incoming]),
                        MAX_REPAIR_REQUESTS_PER_TICK,
                    );
                    metrics.adjacencies[&incoming].observe_repair_suppression(&repair_batch);
                    for request in repair_batch.requests {
                        metrics.adjacencies[&incoming].observe_repair_request(&request);
                        commands[&incoming]
                            .send(MeshTxCommandV2::Control(TxControl::Send(request.encode()?)))
                            .await
                            .context("V2 mesh Repair request writer stopped")?;
                    }
                }
            }
            _ = feedback_tick.tick() => {
                feedback_sequence = feedback_sequence.wrapping_add(1).max(1);
                for (&adjacency, adjacency_metrics) in &metrics.adjacencies {
                    commands[&adjacency]
                        .send(MeshTxCommandV2::Control(TxControl::Send(
                            adjacency_metrics.fec_feedback(feedback_sequence).encode()?,
                        )))
                        .await
                        .context("V2 mesh writer stopped before FEC feedback")?;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn mesh_control_loop(
    network_id: String,
    local_id: EndpointId,
    mut local_presence: SignedPresenceV2,
    secret_key: SecretKey,
    adjacencies: Vec<PeerSessionV2>,
    mut records: mpsc::Receiver<MeshControlRecordV2>,
    mut path_mtu_events: mpsc::Receiver<MeshPathMtuEventV2>,
    repairs: mpsc::Sender<MeshRepairDeliveryV2>,
    routes: mpsc::Sender<RouteAdvertisementV2>,
    snapshots: Arc<DataplaneSnapshotStoreV2>,
    commands: HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    path_mtu_constraints: Arc<RoutePmtuConstraintsV2>,
    allow_default_routes: bool,
    bind: SocketAddr,
    metrics: HashMap<AdjacencyIdV2, Arc<RuntimeMetrics>>,
    runtime_state: Arc<V2RuntimeState>,
    max_total_peers: usize,
) -> Result<()> {
    let mut directory = PresenceDirectoryV2::new(network_id.clone())?;
    directory.insert(local_presence.clone(), SystemTime::now())?;
    runtime_state.publish_presence_directory(&directory, max_total_peers);
    let encoded_local = local_presence.encode()?;
    for sender in commands.values() {
        sender
            .send(MeshTxCommandV2::Control(TxControl::Send(
                encoded_local.clone(),
            )))
            .await
            .context("V2 mesh writer stopped before local Presence")?;
    }
    let mut generation = 1_u64;
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await;
    loop {
        enum Event {
            Record(MeshControlRecordV2),
            PathMtu(MeshPathMtuEventV2),
            Refresh,
        }
        let event = tokio::select! {
            record = records.recv() => {
                Event::Record(record.context("all V2 mesh control readers stopped")?)
            }
            event = path_mtu_events.recv() => {
                Event::PathMtu(event.context("all V2 mesh adjacency writers stopped")?)
            }
            _ = refresh.tick() => {
                Event::Refresh
            }
        };
        let record = match event {
            Event::Record(record) => record,
            Event::PathMtu(event) => {
                commands[&event.incoming]
                    .send(MeshTxCommandV2::Control(TxControl::Send(
                        event.oam.encode()?,
                    )))
                    .await
                    .context("V2 mesh local path-MTU OAM writer stopped")?;
                continue;
            }
            Event::Refresh => {
                refresh_local_presence_paths(&mut local_presence.body, &adjacencies, bind);
                refresh_and_publish_local_presence(
                    &network_id,
                    local_id,
                    &mut local_presence,
                    &secret_key,
                    &mut directory,
                    &mut generation,
                    &routes,
                    &snapshots,
                    &commands,
                    allow_default_routes,
                    &runtime_state,
                    max_total_peers,
                )
                .await?;
                continue;
            }
        };
        metrics
            .get(&record.incoming)
            .context("V2 control record has no adjacency metrics")?
            .observe_control_rx(&record.bytes);
        if SignedPresenceV2::is_record(&record.bytes) {
            let presence = SignedPresenceV2::decode(record.bytes)?;
            apply_mesh_presence(
                &mut directory,
                presence,
                Some(record.incoming),
                &mut generation,
                local_id,
                &routes,
                &snapshots,
                &commands,
                allow_default_routes,
                &runtime_state,
                max_total_peers,
            )
            .await?;
            continue;
        }
        if FecFeedbackV2::is_record(&record.bytes) {
            let feedback = FecFeedbackV2::decode(record.bytes)?;
            let adjacency_metrics = metrics
                .get(&record.incoming)
                .context("V2 FEC feedback has no adjacency metrics")?;
            if adjacency_metrics.apply_remote_feedback(feedback) {
                info!(
                    adjacency = record.incoming.0,
                    sequence = feedback.sequence,
                    parity_received = feedback.parity_received,
                    recovered_cells = feedback.recovered_cells,
                    wasted_parity = feedback.wasted_parity,
                    "applied authenticated V2 directional FEC feedback"
                );
            }
            continue;
        }
        if OamControlV2::is_record(&record.bytes) {
            match OamControlV2::decode(record.bytes)? {
                OamControlV2::TtlExpired(oam) => {
                    if relay_oam_reverse(
                        oam.route_epoch,
                        oam.route_label,
                        oam.encode()?,
                        record.incoming,
                        &snapshots,
                        &commands,
                    )
                    .await?
                    {
                        continue;
                    }
                    runtime_state.publish_ttl_expired(&oam);
                    info!(reporter = ?oam.reporter, hops = oam.traversed_hops, "V2 mesh TTL-expired OAM reached route source");
                }
                OamControlV2::PathMtuExceeded(oam) => {
                    if relay_oam_reverse(
                        oam.route_epoch,
                        oam.route_label,
                        oam.encode()?,
                        record.incoming,
                        &snapshots,
                        &commands,
                    )
                    .await?
                    {
                        continue;
                    }
                    path_mtu_constraints.constrain(
                        oam.route_epoch,
                        oam.route_label,
                        oam.maximum_datagram_size,
                    );
                    info!(
                        reporter = ?oam.reporter,
                        route_epoch = oam.route_epoch,
                        route_label = oam.route_label.0,
                        maximum_datagram_size = oam.maximum_datagram_size,
                        "applied V2 end-to-end path-MTU constraint"
                    );
                }
            }
            continue;
        }
        match RepairControlV2::decode(record.bytes)? {
            RepairControlV2::Request(request) => {
                match snapshots.label_action(
                    request.key.session_epoch,
                    RouteLabelV2::new(request.key.route_label)?,
                ) {
                    Some(LabelActionV2::Forward {
                        expected_ingress,
                        next_hop,
                    }) if record.incoming == next_hop => {
                        commands[&expected_ingress]
                            .send(MeshTxCommandV2::Control(TxControl::Send(request.encode()?)))
                            .await
                            .context("V2 mesh Repair request relay stopped")?;
                    }
                    None => {
                        commands[&record.incoming]
                            .send(MeshTxCommandV2::Control(TxControl::Respond(request)))
                            .await
                            .context("V2 mesh Repair source writer stopped")?;
                    }
                    _ => warn!(
                        incoming = record.incoming.0,
                        "dropped misdirected V2 Repair request"
                    ),
                }
            }
            RepairControlV2::Response(response) => {
                match snapshots.label_action(
                    response.key.session_epoch,
                    RouteLabelV2::new(response.key.route_label)?,
                ) {
                    Some(LabelActionV2::Forward {
                        expected_ingress,
                        next_hop,
                    }) if record.incoming == expected_ingress => {
                        commands[&next_hop]
                            .send(MeshTxCommandV2::Control(TxControl::Send(
                                response.encode()?,
                            )))
                            .await
                            .context("V2 mesh Repair response relay stopped")?;
                    }
                    Some(LabelActionV2::Local { expected_ingress })
                        if record.incoming == expected_ingress =>
                    {
                        repairs
                            .send(MeshRepairDeliveryV2 {
                                incoming: record.incoming,
                                response,
                            })
                            .await
                            .context("V2 mesh local Repair receiver stopped")?;
                    }
                    _ => warn!(
                        incoming = record.incoming.0,
                        "dropped misdirected V2 Repair response"
                    ),
                }
            }
        }
    }
}

fn refresh_local_presence_paths(
    body: &mut PresenceBodyV2,
    adjacencies: &[PeerSessionV2],
    bind: SocketAddr,
) -> bool {
    let mut direct_addresses = adjacencies
        .iter()
        .flat_map(|adjacency| selected_direct_addresses(&adjacency.connection, bind.port()))
        .collect::<Vec<_>>();
    if bind.port() != 0 && !bind.ip().is_unspecified() {
        direct_addresses.push(bind);
    }
    direct_addresses.sort_unstable();
    direct_addresses.dedup();
    direct_addresses.truncate(crate::protocol::v2::presence::MAX_DIRECT_ADDRESSES);

    let mut changed = body.direct_addresses != direct_addresses;
    body.direct_addresses = direct_addresses;
    for link in &mut body.links {
        let Some(adjacency) = adjacencies
            .iter()
            .find(|adjacency| adjacency.remote_id == link.peer)
        else {
            continue;
        };
        let maximum_datagram_size = adjacency
            .connection
            .max_datagram_size()
            .map(|maximum| maximum.min(adjacency.negotiated.limits.max_datagram_size.into()) as u16)
            .unwrap_or(adjacency.negotiated.limits.max_datagram_size);
        let next = PresenceLinkV2 {
            peer: link.peer,
            // Per-second transport quality belongs to the directional
            // autotuner, not the route epoch. Rewriting link cost from a
            // noisy RTT sample on every Presence lease renewal invalidated
            // otherwise identical route labels while queued Bulk Cells were
            // still draining. Keep the authenticated route cost stable for
            // the lifetime of this adjacency; health and PMTU changes below
            // still publish a genuine topology replacement.
            cost: link.cost,
            healthy: adjacency.connection.close_reason().is_none(),
            maximum_datagram_size,
        };
        changed |= *link != next;
        *link = next;
    }
    changed
}

#[allow(clippy::too_many_arguments)]
async fn refresh_and_publish_local_presence(
    network_id: &str,
    local_id: EndpointId,
    local_presence: &mut SignedPresenceV2,
    secret_key: &SecretKey,
    directory: &mut PresenceDirectoryV2,
    generation: &mut u64,
    routes: &mpsc::Sender<RouteAdvertisementV2>,
    snapshots: &DataplaneSnapshotStoreV2,
    commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    allow_default_routes: bool,
    runtime_state: &V2RuntimeState,
    max_total_peers: usize,
) -> Result<()> {
    let now = unix_secs(SystemTime::now())?;
    local_presence.body.sequence = local_presence
        .body
        .sequence
        .checked_add(1)
        .context("V2 local Presence sequence overflow")?;
    local_presence.body.issued_unix_secs = now;
    local_presence.body.expires_unix_secs = now.saturating_add(180);
    *local_presence = SignedPresenceV2::sign(local_presence.body.clone(), secret_key, network_id)?;
    apply_mesh_presence(
        directory,
        local_presence.clone(),
        None,
        generation,
        local_id,
        routes,
        snapshots,
        commands,
        allow_default_routes,
        runtime_state,
        max_total_peers,
    )
    .await
}

async fn relay_oam_reverse(
    route_epoch: u32,
    route_label: RouteLabelV2,
    encoded: Bytes,
    incoming: AdjacencyIdV2,
    snapshots: &DataplaneSnapshotStoreV2,
    commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
) -> Result<bool> {
    let Some(LabelActionV2::Forward {
        expected_ingress,
        next_hop,
    }) = snapshots.label_action(route_epoch, route_label)
    else {
        return Ok(false);
    };
    if incoming != next_hop {
        return Ok(false);
    }
    commands[&expected_ingress]
        .send(MeshTxCommandV2::Control(TxControl::Send(encoded)))
        .await
        .context("V2 mesh reverse OAM writer stopped")?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn apply_mesh_presence(
    directory: &mut PresenceDirectoryV2,
    presence: SignedPresenceV2,
    incoming: Option<AdjacencyIdV2>,
    generation: &mut u64,
    local_id: EndpointId,
    routes: &mpsc::Sender<RouteAdvertisementV2>,
    snapshots: &DataplaneSnapshotStoreV2,
    commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    allow_default_routes: bool,
    runtime_state: &V2RuntimeState,
    max_total_peers: usize,
) -> Result<()> {
    let encoded = presence.encode()?;
    let owner = presence.body.owner;
    let update = directory.insert(presence, SystemTime::now())?;
    if matches!(
        update,
        PresenceUpdateV2::Duplicate | PresenceUpdateV2::Stale
    ) {
        return Ok(());
    }
    for (&adjacency, sender) in commands {
        if incoming != Some(adjacency) {
            sender
                .send(MeshTxCommandV2::Control(TxControl::Send(encoded.clone())))
                .await
                .context("V2 mesh Presence gossip writer stopped")?;
        }
    }
    if update == PresenceUpdateV2::Renewed {
        runtime_state.publish_presence_directory(directory, max_total_peers);
        debug!(%owner, "accepted V2 Presence lease renewal without route epoch churn");
        return Ok(());
    }
    *generation = generation
        .checked_add(1)
        .context("V2 mesh generation overflow")?;
    let route_epoch = u32::try_from(*generation).context("V2 mesh route epoch space exhausted")?;
    let topology = directory.compile_topology(
        *generation,
        route_epoch,
        allow_default_routes,
        SystemTime::now(),
    )?;
    let local = topology
        .snapshot(crate::protocol::v2::routing::NodeIdV2(*local_id.as_bytes()))
        .context("compiled V2 mesh topology omitted local node")?
        .clone();
    let route_count = local.route_count();
    let label_count = local.label_count();
    snapshots.publish(local)?;
    let mut learned_prefixes = directory
        .records()
        .filter(|presence| presence.body.owner != local_id)
        .flat_map(|presence| {
            presence
                .body
                .node_addresses
                .iter()
                .chain(&presence.body.prefixes)
                .copied()
        })
        .collect::<Vec<_>>();
    learned_prefixes
        .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
    learned_prefixes.dedup();
    routes
        .send(RouteAdvertisementV2 {
            generation: *generation,
            prefixes: learned_prefixes,
        })
        .await
        .context("V2 mesh route manager stopped")?;
    runtime_state.publish_presence_directory(directory, max_total_peers);
    info!(
        %owner,
        ?update,
        generation = *generation,
        route_epoch,
        route_count,
        label_count,
        "published authenticated V2 mesh snapshot"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use tokio::sync::mpsc;

    use crate::{protocol::v2::routing::LabelRouteV2, v2_runtime::dataplane::PrioritySendTurnV2};

    use super::*;

    fn product_config() -> crate::config::Config {
        toml::from_str(include_str!("../../config/example.toml")).unwrap()
    }

    #[tokio::test]
    async fn priority_turn_polls_a_ready_send_before_regular_command() {
        let (_priority_sender, mut priority_commands) = mpsc::channel::<()>(1);
        let (commands_sender, mut commands) = mpsc::channel(1);
        commands_sender.send(()).await.unwrap();

        assert_eq!(
            ingress_ready_order(false, PrioritySendTurnV2::PriorityAdmission),
            IngressReadyOrderV2::PriorityThenSendThenRegular
        );
        let selected = tokio::select! {
            biased;
            _ = priority_commands.recv() => "priority",
            _ = std::future::ready(()) => "send",
            _ = commands.recv() => "regular",
        };
        assert_eq!(selected, "send");
        assert_eq!(commands.try_recv(), Ok(()));
    }

    #[tokio::test]
    async fn ttl_oam_is_correlated_to_the_originating_trace_train() {
        let runtime = V2RuntimeConfig::from_product_config(&product_config()).unwrap();
        let local_key = SecretKey::from_bytes(&[61; 32]);
        let reporter_key = SecretKey::from_bytes(&[62; 32]);
        let state = V2RuntimeState::new(&runtime, local_key.public());
        state
            .mesh
            .write()
            .unwrap()
            .nodes
            .push(crate::status::MeshNodeStatus {
                endpoint_id: reporter_key.public().to_string(),
                sequence: 1,
                expires_unix_secs: u64::MAX,
                direct_addresses: Vec::new(),
                node_addresses: vec!["21.0.0.7/32".parse().unwrap()],
                prefixes: Vec::new(),
                transit_enabled: true,
            });
        let route = ResolvedRouteV2 {
            adjacency: AdjacencyIdV2::new(1).unwrap(),
            route_label: RouteLabelV2::new(7).unwrap(),
            route_epoch: 9,
            maximum_datagram_size: 1_382,
        };
        let mut events = state.subscribe_trace_events();
        state.register_trace_train(
            route,
            11,
            TraceProbeTag {
                request_id: 17,
                target: "21.0.0.9".parse().unwrap(),
            },
        );
        state.publish_ttl_expired(&crate::protocol::v2::routing::OamTtlExpiredV2 {
            snapshot_generation: 1,
            route_epoch: route.route_epoch,
            route_label: route.route_label,
            train_id: 11,
            cell_sequence: 0,
            ingress_hop_limit: 1,
            traversed_hops: 1,
            incoming: AdjacencyIdV2::new(1).unwrap(),
            reporter: *reporter_key.public().as_bytes(),
        });

        let event = events.recv().await.unwrap();
        assert_eq!(event.request_id, 17);
        assert_eq!(
            event.reporter_address,
            "21.0.0.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            event.reporter.metadata["endpoint_id"],
            reporter_key.public().to_string()
        );
        assert!(
            state.trace_trains.lock().unwrap().is_empty(),
            "completed trace correlation must not leak pending state"
        );
    }

    #[test]
    fn path_mtu_constraints_only_reduce_the_matching_compiled_route() {
        let constraints = RoutePmtuConstraintsV2::default();
        let route = ResolvedRouteV2 {
            adjacency: AdjacencyIdV2::new(1).unwrap(),
            route_label: RouteLabelV2::new(7).unwrap(),
            route_epoch: 9,
            maximum_datagram_size: 1_382,
        };
        constraints.constrain(9, route.route_label, 1_200);
        constraints.constrain(9, route.route_label, 1_300);
        assert_eq!(constraints.apply(route).maximum_datagram_size, 1_200);

        let mut next_epoch = route;
        next_epoch.route_epoch = 10;
        assert_eq!(constraints.apply(next_epoch).maximum_datagram_size, 1_382);
    }

    #[tokio::test]
    async fn path_oam_uses_the_compiled_reverse_label_action() {
        let incoming = AdjacencyIdV2::new(1).unwrap();
        let outgoing = AdjacencyIdV2::new(2).unwrap();
        let route_label = RouteLabelV2::new(7).unwrap();
        let snapshot = DataplaneSnapshotV2::compile(
            1,
            [3; 32],
            Vec::new(),
            vec![LabelRouteV2 {
                route_label,
                route_epoch: 9,
                action: LabelActionV2::Forward {
                    expected_ingress: incoming,
                    next_hop: outgoing,
                },
            }],
            Vec::new(),
            false,
        )
        .unwrap();
        let snapshots = DataplaneSnapshotStoreV2::new(snapshot);
        let (sender, mut receiver) = mpsc::channel(1);
        let commands = HashMap::from_iter([(incoming, sender)]);
        let encoded = Bytes::from_static(b"oam");
        assert!(
            relay_oam_reverse(
                9,
                route_label,
                encoded.clone(),
                outgoing,
                &snapshots,
                &commands,
            )
            .await
            .unwrap()
        );
        let MeshTxCommandV2::Control(TxControl::Send(delivered)) = receiver.recv().await.unwrap()
        else {
            panic!("expected reverse OAM control record");
        };
        assert_eq!(delivered, encoded);
    }
}
