//! Shared TUN ingress and the single-peer V2 dataplane loops.
//!
//! The mesh runtime keeps its own adjacency loops in the parent module and
//! consumes the explicit `pub(super)` ingress, timing, and output primitives
//! defined here. No scheduling or FEC policy is reinterpreted at this boundary.

use std::{
    collections::VecDeque,
    hash::{Hash, Hasher},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use ipnet::IpNet;
use iroh::{EndpointId, SecretKey, endpoint::Connection};
use rustc_hash::{FxHashMap as HashMap, FxHasher};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tracing::{debug, info, warn};
use tun_rs::{
    IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6,
    VIRTIO_NET_HDR_GSO_UDP_L4, VIRTIO_NET_HDR_LEN, VirtioNetHdr, gso_split,
};

use super::{
    V2RuntimeState,
    host_network::KernelRoutePolicyV2,
    telemetry::{RuntimeMetrics, TunIngressBatchV2, increment_sampled_counter},
};
use crate::{
    buffer::PacketSlotPool,
    packet::{FlowKey, PacketInfo, icmpv4_echo_probe, inspect_ip_packet, ip_hop_limit_validated},
    protocol::v2::{
        cell::TrafficClass,
        classifier::{ClassifierConfig, FlowClassifier},
        cover::CoverPaddingV2,
        dataplane::{
            MAX_REPAIR_REQUESTS_PER_TICK, V2ControlRx, V2Rx, V2Tx, completed_record_to_tun,
        },
        feedback::FecFeedbackV2,
        gso::{GsoObservationV2, encode_train_record_observed},
        presence::{PresenceDirectoryV2, PresenceUpdateV2, SignedPresenceV2},
        reassembly::ReassemblyOutput,
        repair::{RepairControlV2, RepairRequestV2, RepairResponseV2},
        routing::{AdjacencyIdV2, DataplaneSnapshotV2, RouteAdvertisementV2, TransitDispositionV2},
        scheduler::SchedulerLimits,
        tuning::{AutoTuneBoundsV2, CoverTrafficProfileV2, RepairWaitPolicyV2, TuneDecisionV2},
    },
};

const RAW_TUN_BYTES: usize = VIRTIO_NET_HDR_LEN + u16::MAX as usize;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;
pub(super) const TUN_INPUT_SLOTS: usize = 64;
pub(super) const TUN_PRIORITY_INPUT_SLOTS: usize = 128;
const TX_BULK_ADMISSION_HIGH_WATER_BYTES: usize = 512 * 1024;
pub(super) const TX_LATENCY_ADMISSION_HIGH_WATER_BYTES: usize = 128 * 1024;
// Keep each adjacency's ordinary scheduler admission shallow enough that an
// inner TCP sender observes the real path rather than the upstream merge
// burst budget. The hard scheduler limits remain larger for control/repair
// safety; this is the normal producer watermark, with a separately driven
// strict-priority path.
const TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES: usize = 512 * 1024;
pub(super) const TX_ADMISSION_BATCH_BYTES: usize = 128 * 1024;
pub(super) const MAX_CLASSIFIERS: usize = 65_536;
pub(super) const CLASSIFIER_IDLE: Duration = Duration::from_secs(60);

/// Bounds the number of scheduler sends that may overtake a ready strict
/// priority admission. One send is enough to make progress for a preceding
/// TUN batch, while a longer burst made the reserved ICMP/ACK lane wait
/// behind a full paced quantum sequence on shallow paths.
const MAX_SENDS_BETWEEN_PRIORITY_ADMISSIONS: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrioritySendTurnV2 {
    PriorityAdmission,
    Send,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrioritySendArbiterV2 {
    sends_since_priority: u8,
}

impl Default for PrioritySendArbiterV2 {
    fn default() -> Self {
        Self {
            sends_since_priority: MAX_SENDS_BETWEEN_PRIORITY_ADMISSIONS,
        }
    }
}

impl PrioritySendArbiterV2 {
    pub(super) fn next(&self) -> PrioritySendTurnV2 {
        if self.sends_since_priority >= MAX_SENDS_BETWEEN_PRIORITY_ADMISSIONS {
            PrioritySendTurnV2::PriorityAdmission
        } else {
            PrioritySendTurnV2::Send
        }
    }

    pub(super) fn admitted_priority(&mut self) {
        self.sends_since_priority = 0;
    }

    pub(super) fn completed_send(&mut self) {
        self.sends_since_priority = self.sends_since_priority.saturating_add(1);
    }
}

/// The first ready ingress future wins because the TX loops deliberately use
/// `tokio::select! { biased; }`. Keep this order as a data-only helper so the
/// single-peer and mesh loops retain the same ready-race contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IngressReadyOrderV2 {
    PriorityThenSend,
    SendThenPriority,
    PriorityThenSendThenRegular,
    SendThenPriorityThenRegular,
}

pub(super) fn ingress_ready_order(
    saturated: bool,
    priority_turn: PrioritySendTurnV2,
) -> IngressReadyOrderV2 {
    match (saturated, priority_turn) {
        (true, PrioritySendTurnV2::PriorityAdmission) => IngressReadyOrderV2::PriorityThenSend,
        (true, PrioritySendTurnV2::Send) => IngressReadyOrderV2::SendThenPriority,
        (false, PrioritySendTurnV2::PriorityAdmission) => {
            IngressReadyOrderV2::PriorityThenSendThenRegular
        }
        (false, PrioritySendTurnV2::Send) => IngressReadyOrderV2::SendThenPriorityThenRegular,
    }
}

/// A raw TUN record plus its byte-budget ownership. Slot-bounded channels are
/// insufficient here because one slot may hold either a 60-byte ACK or a
/// 65-KiB GSO record. The permit remains attached until the dispatcher
/// actually consumes the record, making the admission edge byte-bounded
/// without a mutex or a second queue-length state machine. A one-shot GSO
/// observation follows the first admitted segment so mesh routing can charge
/// the original aggregate to the selected adjacency.
pub(super) struct TunIngressRecordV2 {
    pub(super) bytes: Bytes,
    pub(super) info: PacketInfo,
    pub(super) gso: GsoObservationV2,
    pub(super) _permit: Option<OwnedSemaphorePermit>,
}

impl TunIngressRecordV2 {
    fn priority(bytes: Bytes, info: PacketInfo) -> Self {
        Self {
            bytes,
            info,
            gso: GsoObservationV2::default(),
            _permit: None,
        }
    }

    fn regular(bytes: Bytes, info: PacketInfo, permit: OwnedSemaphorePermit) -> Self {
        Self {
            bytes,
            info,
            gso: GsoObservationV2::default(),
            _permit: Some(permit),
        }
    }

    fn with_gso_observation(mut self, gso: GsoObservationV2) -> Self {
        self.gso = gso;
        self
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

pub(super) fn minimum_receive_buffer_bytes() -> usize {
    AutoTuneBoundsV2::default().minimum_receive_buffer_bytes
}

pub(super) fn apply_receive_buffer_target(
    rx: &mut V2Rx,
    metrics: &RuntimeMetrics,
) -> Result<usize> {
    let mut evicted = 0;
    // The policy-driven reassembly budget and active-train budget ride the
    // same metrics channel as the receive buffer target.
    let budget = metrics.reassembly_budget_bytes.load(Ordering::Relaxed) as usize;
    let trains = metrics.active_train_budget.load(Ordering::Relaxed) as usize;
    if budget != rx.reassembly_budget_bytes() || trains != rx.active_train_budget() {
        evicted += rx.set_reassembly_budget(budget, trains)?;
    }
    let target = metrics.receive_buffer_bytes.load(Ordering::Relaxed) as usize;
    if target != 0 && target != rx.maximum_buffered_bytes() {
        evicted += rx.set_maximum_buffered_bytes(target)?;
    }
    Ok(evicted)
}

#[derive(Debug)]
pub(super) struct CoverShaperV2 {
    profile: CoverTrafficProfileV2,
    bytes_per_second: u64,
    tokens: u64,
    updated_at: Instant,
}

impl Default for CoverShaperV2 {
    fn default() -> Self {
        Self {
            profile: CoverTrafficProfileV2::Idle,
            bytes_per_second: 0,
            tokens: 0,
            updated_at: Instant::now(),
        }
    }
}

impl CoverShaperV2 {
    pub(super) fn update(&mut self, decision: TuneDecisionV2) {
        self.refill();
        self.profile = decision.cover_profile;
        self.bytes_per_second = decision.cover_padding_bytes_per_second;
        if self.bytes_per_second == 0 || self.profile == CoverTrafficProfileV2::Idle {
            self.tokens = 0;
        } else {
            self.tokens = self.tokens.min(self.maximum_tokens());
        }
    }

    pub(super) fn enqueue_after_real(&mut self, tx: &mut V2Tx) -> Result<usize> {
        if self.bytes_per_second == 0 || self.profile == CoverTrafficProfileV2::Idle {
            return Ok(0);
        }
        self.refill();
        let target = tx.cover_padding_target_size(self.profile)?;
        if self.tokens < target as u64 || !tx.enqueue_cover_padding(self.profile)? {
            return Ok(0);
        }
        self.tokens -= target as u64;
        Ok(target)
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_nanos = now.saturating_duration_since(self.updated_at).as_nanos();
        self.updated_at = now;
        if self.bytes_per_second == 0 {
            return;
        }
        let added = u128::from(self.bytes_per_second).saturating_mul(elapsed_nanos) / 1_000_000_000;
        self.tokens = self
            .tokens
            .saturating_add(added.min(u64::MAX.into()) as u64)
            .min(self.maximum_tokens());
    }

    fn maximum_tokens(&self) -> u64 {
        // At most 100 ms of the automatically derived budget may accumulate;
        // this prevents a low-rate flow from later emitting a cover burst.
        (self.bytes_per_second / 10).max(2_048)
    }
}

#[derive(Debug)]
struct FlowState {
    classifier: FlowClassifier,
    last_seen: Duration,
}

#[derive(Debug)]
pub(super) enum TxControl {
    Send(Bytes),
    Respond(RepairRequestV2),
}

#[derive(Debug)]
pub(super) struct ControlContextV2 {
    pub(super) tx: mpsc::Sender<TxControl>,
    pub(super) repaired: mpsc::Sender<RepairResponseV2>,
    pub(super) routes: mpsc::Sender<RouteAdvertisementV2>,
    pub(super) presences: mpsc::Sender<SignedPresenceV2>,
    pub(super) allow_default_routes: bool,
    pub(super) metrics: Arc<RuntimeMetrics>,
}

#[derive(Debug, Clone)]
pub(super) struct RxRouteContext {
    pub(super) snapshot: Arc<DataplaneSnapshotV2>,
    pub(super) incoming: AdjacencyIdV2,
}

/// Read hard latency traffic into a reserved ingress lane. The mesh runtime
/// drives regular and priority dispatchers independently. Ordinary traffic
/// is byte-bounded with backpressure rather than userspace tail-drop: dropping
/// an inner TCP packet here is invisible to QUIC/BBR and previously collapsed
/// throughput long before the real underlay bottleneck was reached.
pub(super) async fn prioritized_tun_reader(
    device: Arc<tun_rs::AsyncDevice>,
    regular: mpsc::Sender<TunIngressRecordV2>,
    priority: mpsc::Sender<TunIngressRecordV2>,
    regular_budget: Arc<Semaphore>,
    metrics: Arc<RuntimeMetrics>,
    tun_mtu: u16,
) -> Result<()> {
    let mut pool = PacketSlotPool::with_payload_sizes(1, 0, RAW_TUN_BYTES, RAW_TUN_BYTES);
    let mut split_pool = PacketSlotPool::with_payload_sizes(
        IDEAL_BATCH_SIZE,
        0,
        VIRTIO_NET_HDR_LEN + 4 * 1024,
        RAW_TUN_BYTES,
    );
    let mut split_sizes = vec![0_usize; IDEAL_BATCH_SIZE];
    loop {
        let length = device
            .recv(&mut pool.slots_mut()[0])
            .await
            .context("reading raw prioritized V2 TUN record")?;
        if length <= VIRTIO_NET_HDR_LEN {
            pool.recycle_empty(0);
            warn!(length, "dropped truncated raw V2 TUN record");
            continue;
        }
        let info = match inspect_ip_packet(&pool.slots_mut()[0][VIRTIO_NET_HDR_LEN..length]) {
            Ok(info) => info,
            Err(error) => {
                warn!(%error, "dropped invalid V2 IP input at TUN admission");
                continue;
            }
        };
        metrics.tun_tx_packets.fetch_add(1, Ordering::Relaxed);
        let regular_admission_ready =
            regular.capacity() > 0 && regular_budget.available_permits() >= length;
        let oversized = tun_record_exceeds_mtu(length, tun_mtu);
        if !oversized && (info.latency_protected || regular_admission_ready) {
            // The common path neither decodes nor rewrites the virtio header.
            // A configured 32-KiB TUN MTU bounds ordinary records, while the
            // kernel may still hand us a larger GSO aggregate for amortized
            // reads; only those aggregates need software segmentation.
            let record = pool.take(0, length);
            if info.latency_protected {
                if let Some((kind, sequence)) = icmpv4_echo_probe(&record[VIRTIO_NET_HDR_LEN..]) {
                    tracing::trace!(
                        target: "ironet::latency_probe",
                        stage = "tun-read",
                        kind,
                        sequence,
                        "V2 ICMP latency probe"
                    );
                }
                priority
                    .send(TunIngressRecordV2::priority(record, info))
                    .await
                    .context("V2 priority TX task stopped")?;
            } else {
                try_admit_regular_tun_record(&regular, &regular_budget, record, info, &metrics)?;
            }
        } else {
            // Admission overload must not stop reading the TUN: doing so moves
            // the queue into the opaque kernel/TUN ring and leaves ICMP, ACKs
            // and FINs behind seconds of stale bulk data. If this is a large
            // TCP/UDP GSO record, split it before controlled tail shedding.
            // Independently, split an aggregate larger than the configured
            // TUN MTU even without admission pressure: preserving that 64-KiB
            // failure domain would undo the MTU bound after one lost Cell.
            let header = VirtioNetHdr::decode(&pool.slots_mut()[0][..VIRTIO_NET_HDR_LEN])
                .context("decoding V2 TUN virtio header for bounded admission")?;
            let Some(split_header) = normalized_tun_gso_header(header) else {
                record_invalid_tun_gso_type(&metrics, length, header.gso_type);
                continue;
            };
            if !should_split_tun_gso_record(
                length,
                tun_mtu,
                split_header.gso_type,
                !info.latency_protected && !regular_admission_ready,
            ) {
                let record = pool.take(0, length);
                if info.latency_protected {
                    priority
                        .send(TunIngressRecordV2::priority(record, info))
                        .await
                        .context("V2 priority TX task stopped")?;
                } else {
                    try_admit_regular_tun_record(
                        &regular,
                        &regular_budget,
                        record,
                        info,
                        &metrics,
                    )?;
                }
                continue;
            }
            split_sizes.fill(0);
            let ip_version = pool.slots_mut()[0][VIRTIO_NET_HDR_LEN] >> 4;
            let segments = gso_split(
                &mut pool.slots_mut()[0][VIRTIO_NET_HDR_LEN..length],
                split_header,
                split_pool.slots_mut(),
                &mut split_sizes,
                VIRTIO_NET_HDR_LEN,
                ip_version == 6,
            );
            let segments = match segments {
                Ok(segments) => segments,
                Err(error) => {
                    let (errors, sampled) = metrics.record_protocol_datagram_error();
                    if sampled {
                        warn!(
                            %error,
                            errors,
                            length,
                            gso_type = split_header.gso_type,
                            "dropped invalid V2 TUN GSO record"
                        );
                    }
                    continue;
                }
            };
            let mut gso_observation =
                tun_gso_fallback_observation(length.saturating_sub(VIRTIO_NET_HDR_LEN));
            pool.recycle_empty(0);
            for (index, payload_len) in split_sizes.iter().copied().take(segments).enumerate() {
                split_pool.slots_mut()[index][..VIRTIO_NET_HDR_LEN].fill(0);
                let record = split_pool.take(index, VIRTIO_NET_HDR_LEN + payload_len);
                let info = match inspect_ip_packet(&record[VIRTIO_NET_HDR_LEN..]) {
                    Ok(segment_info) => {
                        inherit_aggregate_latency_class(segment_info, info.latency_protected)
                    }
                    Err(error) => {
                        warn!(%error, "dropped invalid split V2 IP input at TUN admission");
                        continue;
                    }
                };
                metrics.tun_tx_packets.fetch_add(1, Ordering::Relaxed);
                if info.latency_protected {
                    let record = TunIngressRecordV2::priority(record, info)
                        .with_gso_observation(gso_observation);
                    priority
                        .send(record)
                        .await
                        .context("V2 priority TX task stopped")?;
                    gso_observation = GsoObservationV2::default();
                } else {
                    if try_admit_regular_tun_record_observed(
                        &regular,
                        &regular_budget,
                        record,
                        info,
                        gso_observation,
                        &metrics,
                    )? {
                        gso_observation = GsoObservationV2::default();
                    }
                }
            }
        }
    }
}

fn tun_record_exceeds_mtu(record_len: usize, tun_mtu: u16) -> bool {
    record_len.saturating_sub(VIRTIO_NET_HDR_LEN) > usize::from(tun_mtu)
}

/// tun-rs dispatches TCP versus UDP by exact GSO-type equality. The ECN bit is
/// virtio metadata rather than a distinct segmentation algorithm, so validate
/// the base type and remove the bit before calling tun-rs.
fn normalized_tun_gso_header(mut header: VirtioNetHdr) -> Option<VirtioNetHdr> {
    let base_type = header.gso_type & !VIRTIO_NET_HDR_GSO_ECN;
    if !matches!(
        base_type,
        VIRTIO_NET_HDR_GSO_NONE
            | VIRTIO_NET_HDR_GSO_TCPV4
            | VIRTIO_NET_HDR_GSO_TCPV6
            | VIRTIO_NET_HDR_GSO_UDP_L4
    ) {
        return None;
    }
    header.gso_type = base_type;
    Some(header)
}

fn inherit_aggregate_latency_class(
    mut segment: crate::packet::PacketInfo,
    aggregate_latency_protected: bool,
) -> crate::packet::PacketInfo {
    // All segments from one aggregate use one FIFO lane. In particular,
    // tun-rs clears FIN on non-final TCP segments; reclassifying them
    // independently would let the final priority FIN overtake its payload.
    segment.latency_protected = aggregate_latency_protected;
    segment
}

fn tun_gso_fallback_observation(input_bytes: usize) -> GsoObservationV2 {
    GsoObservationV2 {
        input_bytes: u64::try_from(input_bytes).unwrap_or(u64::MAX),
        preserved_bytes: 0,
        fallback_splits: 1,
    }
}

fn record_invalid_tun_gso_type(metrics: &RuntimeMetrics, bytes: usize, gso_type: u8) {
    let (errors, sampled) = metrics.record_protocol_datagram_error();
    if sampled {
        warn!(
            errors,
            bytes, gso_type, "dropped V2 TUN record with unsupported GSO type"
        );
    }
}

fn should_split_tun_gso_record(
    record_len: usize,
    tun_mtu: u16,
    gso_type: u8,
    regular_admission_overloaded: bool,
) -> bool {
    gso_type != VIRTIO_NET_HDR_GSO_NONE
        && (regular_admission_overloaded || tun_record_exceeds_mtu(record_len, tun_mtu))
}

fn try_admit_regular_tun_record(
    regular: &mpsc::Sender<TunIngressRecordV2>,
    regular_budget: &Arc<Semaphore>,
    record: Bytes,
    info: crate::packet::PacketInfo,
    metrics: &RuntimeMetrics,
) -> Result<bool> {
    try_admit_regular_tun_record_observed(
        regular,
        regular_budget,
        record,
        info,
        GsoObservationV2::default(),
        metrics,
    )
}

fn try_admit_regular_tun_record_observed(
    regular: &mpsc::Sender<TunIngressRecordV2>,
    regular_budget: &Arc<Semaphore>,
    record: Bytes,
    info: crate::packet::PacketInfo,
    gso: GsoObservationV2,
    metrics: &RuntimeMetrics,
) -> Result<bool> {
    let length = record.len();
    let permits = u32::try_from(record.len()).context("V2 TUN record length overflow")?;
    let Ok(permit) = regular_budget.clone().try_acquire_many_owned(permits) else {
        record_tun_admission_drop(metrics, length);
        return Ok(false);
    };
    match regular
        .try_send(TunIngressRecordV2::regular(record, info, permit).with_gso_observation(gso))
    {
        Ok(()) => Ok(true),
        Err(mpsc::error::TrySendError::Full(record)) => {
            record_tun_admission_drop(metrics, record.len());
            Ok(false)
        }
        Err(mpsc::error::TrySendError::Closed(_)) => bail!("V2 TX task stopped"),
    }
}

fn record_tun_admission_drop(metrics: &RuntimeMetrics, bytes: usize) {
    let (records, sampled) = increment_sampled_counter(&metrics.tun_admission_drop_records);
    let total_bytes = metrics
        .tun_admission_drop_bytes
        .fetch_add(bytes as u64, Ordering::Relaxed)
        .saturating_add(bytes as u64);
    if sampled {
        warn!(
            records,
            total_bytes, "shed overloaded V2 regular TUN segment at observable admission edge"
        );
    }
}

pub(super) struct PrioritizedTunInput {
    pub(super) regular: mpsc::Receiver<TunIngressRecordV2>,
    pub(super) priority: mpsc::Receiver<TunIngressRecordV2>,
}

pub(super) async fn tx_loop(
    connection: Connection,
    negotiated: crate::protocol::v2::session::NegotiatedSessionV2,
    mut input: PrioritizedTunInput,
    mut tuning: watch::Receiver<Option<TuneDecisionV2>>,
    mut control: mpsc::Receiver<TxControl>,
    metrics: Arc<RuntimeMetrics>,
    route_label: u32,
) -> Result<()> {
    enum Event {
        Input(Option<TunIngressRecordV2>),
        PriorityInput(Option<TunIngressRecordV2>),
        Control(Option<TxControl>),
        Tuned,
        Sent(Result<Option<crate::protocol::v2::dataplane::SendProgress>>),
    }

    let mut tx = V2Tx::new(connection, negotiated, SchedulerLimits::default())?;
    let started = Instant::now();
    let mut classifiers = HashMap::<FlowKey, FlowState>::default();
    let mut receive_batch = 8_usize;
    let mut applied_tuning = None::<TuneDecisionV2>;
    let mut cover_shaper = CoverShaperV2::default();
    let mut deferred_input = VecDeque::<TunIngressRecordV2>::new();
    let mut priority_send = PrioritySendArbiterV2::default();
    loop {
        // Preserve a bounded receive burst as one aggregation opportunity.
        // The scheduler still owns hard memory admission, while the local
        // byte ceiling prevents a 64-entry GSO burst from overshooting its
        // high-water mark. One-record admission made every PacketTrain too
        // short for a real FEC stripe and defeated train packing entirely.
        let depth = tx.depth();
        let high_water = tx_admission_high_water(&tx);
        if !admission_saturated(depth, high_water) && !deferred_input.is_empty() {
            let available =
                high_water.saturating_sub(depth.bulk_bytes.saturating_add(depth.latency_bytes));
            let batch = drain_tun_ingress_batch(
                &mut deferred_input,
                receive_batch,
                available.min(TX_ADMISSION_BATCH_BYTES),
            );
            enqueue_tun_batch(
                &mut tx,
                &mut classifiers,
                started.elapsed(),
                route_label,
                batch,
                false,
                &metrics,
            )?;
        }
        let depth = tx.depth();
        let event = if tx.has_pending() && admission_saturated(depth, high_water) {
            if ingress_ready_order(true, priority_send.next())
                == IngressReadyOrderV2::PriorityThenSend
            {
                tokio::select! {
                    biased;
                    changed = tuning.changed() => {
                        changed.context("V2 tuner stopped")?;
                        Event::Tuned
                    }
                    record = input.priority.recv() => Event::PriorityInput(record),
                    sent = tx.send_next() => Event::Sent(sent),
                    command = control.recv() => Event::Control(command),
                }
            } else {
                tokio::select! {
                    biased;
                    changed = tuning.changed() => {
                        changed.context("V2 tuner stopped")?;
                        Event::Tuned
                    }
                    sent = tx.send_next() => Event::Sent(sent),
                    record = input.priority.recv() => Event::PriorityInput(record),
                    command = control.recv() => Event::Control(command),
                }
            }
        } else if tx.has_pending() || !deferred_input.is_empty() {
            if ingress_ready_order(false, priority_send.next())
                == IngressReadyOrderV2::PriorityThenSendThenRegular
            {
                tokio::select! {
                    biased;
                    changed = tuning.changed() => {
                        changed.context("V2 tuner stopped")?;
                        Event::Tuned
                    }
                    record = input.priority.recv() => Event::PriorityInput(record),
                    sent = tx.send_next() => Event::Sent(sent),
                    record = input.regular.recv() => Event::Input(record),
                    command = control.recv() => Event::Control(command),
                }
            } else {
                tokio::select! {
                    biased;
                    changed = tuning.changed() => {
                        changed.context("V2 tuner stopped")?;
                        Event::Tuned
                    }
                    sent = tx.send_next() => Event::Sent(sent),
                    record = input.priority.recv() => Event::PriorityInput(record),
                    record = input.regular.recv() => Event::Input(record),
                    command = control.recv() => Event::Control(command),
                }
            }
        } else {
            tokio::select! {
                biased;
                record = input.priority.recv() => Event::PriorityInput(record),
                changed = tuning.changed() => {
                    changed.context("V2 tuner stopped")?;
                    Event::Tuned
                }
                record = input.regular.recv() => Event::Input(record),
                command = control.recv() => Event::Control(command),
            }
        };
        match event {
            Event::Tuned => {
                if let Some(decision) = *tuning.borrow_and_update() {
                    receive_batch = decision.receive_batch;
                    if applied_tuning.is_none_or(|current| {
                        effective_tx_tuning(current) != effective_tx_tuning(decision)
                    }) {
                        tx.apply_tuning(decision)?;
                        cover_shaper.update(decision);
                        info!(
                            reason = ?decision.reason,
                            train_bytes = decision.train_target_bytes,
                            quantum_cells = decision.bulk_quantum_cells,
                            fec = ?decision.fec,
                            send_buffer_bytes = decision.send_buffer_bytes,
                            datagram_admission_bytes = tx.datagram_send_buffer_limit(),
                            receive_buffer_bytes = decision.receive_buffer_bytes,
                            receive_batch,
                            cover_profile = ?decision.cover_profile,
                            cover_overhead_per_mille = decision.cover_overhead_per_mille,
                            cover_padding_bytes_per_second = decision.cover_padding_bytes_per_second,
                            "applied automatic V2 tuning decision"
                        );
                        applied_tuning = Some(decision);
                    }
                }
            }
            Event::Input(None) => bail!("all V2 TUN readers stopped"),
            Event::PriorityInput(None) => bail!("all V2 priority TUN readers stopped"),
            Event::PriorityInput(Some(first)) => {
                priority_send.admitted_priority();
                let mut batch = Vec::with_capacity(receive_batch);
                batch.push(first);
                while batch.len() < receive_batch {
                    match input.priority.try_recv() {
                        Ok(record) => batch.push(record),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                enqueue_tun_batch(
                    &mut tx,
                    &mut classifiers,
                    started.elapsed(),
                    route_label,
                    batch,
                    true,
                    &metrics,
                )?;
            }
            Event::Control(None) => bail!("V2 control receiver stopped"),
            Event::Control(Some(TxControl::Send(record))) => {
                metrics.observe_control_tx(&record);
                ensure!(tx.enqueue_control(record)?, "V2 control queue is full");
            }
            Event::Control(Some(TxControl::Respond(request))) => {
                let response = tx.repair_response(&request).encode()?;
                metrics.observe_control_tx(&response);
                ensure!(tx.enqueue_control(response)?, "V2 control queue is full");
            }
            Event::Input(Some(first)) => {
                let mut batch = Vec::with_capacity(receive_batch);
                batch.push(first);
                while batch.len() < receive_batch {
                    match input.regular.try_recv() {
                        Ok(record) => batch.push(record),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                deferred_input.extend(batch);
                if classifiers.len() > MAX_CLASSIFIERS {
                    let now = started.elapsed();
                    classifiers
                        .retain(|_, state| now.saturating_sub(state.last_seen) < CLASSIFIER_IDLE);
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
                    let previous_pmtu_drops = metrics
                        .pmtu_drop_datagrams
                        .fetch_add(progress.dropped_datagrams as u64, Ordering::Relaxed);
                    if progress.dropped_datagrams != 0 && previous_pmtu_drops == 0 {
                        warn!(
                            datagrams = progress.dropped_datagrams,
                            bytes = progress.dropped_bytes,
                            "retiring stale V2 Cells after live PMTU shrink; further drops are counted without per-quantum logs"
                        );
                    }
                    if sent_real && !tx.has_pending() && deferred_input.is_empty() {
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

pub(super) fn tx_admission_high_water(tx: &V2Tx) -> usize {
    tx.datagram_send_buffer_limit().clamp(
        TX_ADMISSION_BATCH_BYTES,
        TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES,
    )
}

pub(super) fn admission_saturated(
    depth: crate::protocol::v2::scheduler::SchedulerDepth,
    application_high_water: usize,
) -> bool {
    depth.bulk_bytes >= TX_BULK_ADMISSION_HIGH_WATER_BYTES.min(application_high_water)
        || depth.latency_bytes >= TX_LATENCY_ADMISSION_HIGH_WATER_BYTES.min(application_high_water)
        || depth.bulk_bytes.saturating_add(depth.latency_bytes) >= application_high_water
}

pub(super) fn repair_minimum_age_for_rtt(rtt: Duration) -> Duration {
    // QUIC DATAGRAM delivery, PacketTrain scheduling and a shallow policer can
    // reorder Cells across several scheduler/ACK rounds even on a 3-6 ms path.
    // A 10 ms floor treated that harmless delay as loss and sent reliable
    // responses into the same bottleneck. Eight RTTs with a 50 ms floor still
    // beats the inner TCP RTO, while forward progress restarts this grace
    // period and the ceiling keeps Repair useful after migration.
    rtt.saturating_mul(8)
        .clamp(Duration::from_millis(50), Duration::from_secs(1))
}

pub(super) fn adaptive_repair_minimum_age(metrics: &RuntimeMetrics) -> Duration {
    let micros = metrics.repair_minimum_age_micros.load(Ordering::Relaxed);
    let base = if micros == 0 {
        Duration::from_millis(100)
    } else {
        Duration::from_micros(micros)
    };
    match RepairWaitPolicyV2::from_metrics_code(metrics.repair_wait_policy.load(Ordering::Relaxed))
    {
        RepairWaitPolicyV2::Eager => base / 2,
        // Doubling the RTT-derived wait adds roughly one RTT of reorder
        // tolerance; the ceiling keeps Repair responsive after migration.
        RepairWaitPolicyV2::Patient => base.saturating_mul(2).min(Duration::from_secs(2)),
        RepairWaitPolicyV2::HostDefault | RepairWaitPolicyV2::AfterFecWindow => base,
    }
}

pub(super) fn drain_tun_ingress_batch(
    pending: &mut VecDeque<TunIngressRecordV2>,
    maximum_records: usize,
    maximum_bytes: usize,
) -> Vec<TunIngressRecordV2> {
    let mut output = Vec::with_capacity(maximum_records.min(pending.len()));
    let mut bytes = 0_usize;
    while output.len() < maximum_records {
        let Some(next) = pending.front() else {
            break;
        };
        if !output.is_empty() && bytes.saturating_add(next.len()) > maximum_bytes {
            break;
        }
        let next = pending.pop_front().expect("front record remains queued");
        bytes = bytes.saturating_add(next.len());
        output.push(next);
    }
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EffectiveTuneV2 {
    train_target_bytes: usize,
    bulk_quantum_cells: usize,
    fec: Option<crate::protocol::v2::fec::FecGeometryV2>,
    repair_cache_bytes: usize,
    repair_retention_millis: u32,
    send_buffer_bytes: usize,
    receive_batch: usize,
    cover_profile: CoverTrafficProfileV2,
    cover_overhead_per_mille: u16,
    cover_padding_bytes_per_second: u64,
}

pub(super) fn effective_tx_tuning(decision: TuneDecisionV2) -> EffectiveTuneV2 {
    EffectiveTuneV2 {
        train_target_bytes: decision.train_target_bytes,
        bulk_quantum_cells: decision.bulk_quantum_cells,
        fec: decision.fec,
        repair_cache_bytes: decision.repair_cache_bytes,
        repair_retention_millis: decision.repair_retention_millis,
        send_buffer_bytes: decision.send_buffer_bytes,
        receive_batch: decision.receive_batch,
        cover_profile: decision.cover_profile,
        cover_overhead_per_mille: decision.cover_overhead_per_mille,
        cover_padding_bytes_per_second: decision.cover_padding_bytes_per_second,
    }
}

fn enqueue_tun_batch(
    tx: &mut V2Tx,
    classifiers: &mut HashMap<FlowKey, FlowState>,
    now: Duration,
    route_label: u32,
    records: Vec<TunIngressRecordV2>,
    hard_latency: bool,
    metrics: &RuntimeMetrics,
) -> Result<()> {
    // A Cell has one fixed routing shim. Grouping by ingress IP hop limit
    // makes its overlay budget the exact TTL/Hop-Limit of every contained
    // record instead of weakening it to a train-wide default.
    let mut grouped = HashMap::<(u64, TrafficClass, u8), Vec<(Bytes, Bytes)>>::default();
    let mut ingress = TunIngressBatchV2::default();
    for record in records {
        let TunIngressRecordV2 {
            bytes: raw,
            info,
            gso: reader_gso,
            _permit: _,
        } = record;
        let packet = &raw[VIRTIO_NET_HDR_LEN..];
        let packet_len = packet.len();
        let key = FlowKey::from(info);
        let flow_id = flow_id(key);
        let overlay_hop_limit = ip_hop_limit_validated(packet);
        if overlay_hop_limit == 0 {
            warn!("dropped V2 IP input with exhausted hop limit");
            continue;
        }
        let state = classifiers.entry(key).or_insert_with(|| FlowState {
            classifier: FlowClassifier::new(ClassifierConfig::default(), now),
            last_seen: now,
        });
        state.last_seen = now;
        let class = state
            .classifier
            .observe(now, packet_len, 0, info.latency_protected);
        let (metadata, data, mut gso) = match encode_train_record_observed(raw) {
            Ok(record) => record,
            Err(error) => {
                warn!(%error, "dropped invalid V2 GSO metadata");
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
        ingress.observe(packet_len, gso);
        grouped
            .entry((flow_id, class, overlay_hop_limit))
            .or_default()
            .push((metadata, data));
    }
    for ((flow_id, class, overlay_hop_limit), records) in grouped {
        let records = records
            .into_iter()
            .enumerate()
            .map(|(index, (metadata, data))| {
                Ok(crate::protocol::v2::train::TrainRecord {
                    record_id: u16::try_from(index + 1)
                        .context("V2 TUN batch has too many records")?,
                    metadata,
                    data,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if hard_latency {
            tracing::trace!(
                target: "ironet::latency_probe",
                stage = "scheduler-admit",
                flow_id,
                records = records.len(),
                "V2 strict latency batch"
            );
        }
        let admitted = tx.enqueue_records_auto_with_hop_limit_and_priority(
            flow_id,
            class,
            route_label,
            overlay_hop_limit,
            records,
            hard_latency,
        )?;
        ensure!(
            !admitted.is_empty(),
            "V2 scheduler rejected a TUN PacketTrain"
        );
    }
    metrics.observe_tun_ingress_batch(ingress);
    Ok(())
}

pub(super) async fn rx_loop(
    connection: Connection,
    negotiated: crate::protocol::v2::session::NegotiatedSessionV2,
    mut writer: crate::tunnel::OverlayTunnelWriter,
    metrics: Arc<RuntimeMetrics>,
    control: mpsc::Sender<TxControl>,
    mut repaired: mpsc::Receiver<RepairResponseV2>,
    route: RxRouteContext,
) -> Result<()> {
    let mut rx = V2Rx::new(connection, negotiated, minimum_receive_buffer_bytes())?;
    // This only drains DATAGRAMs already buffered by QUIC, so using the
    // negotiated maximum never waits or adds latency. RX FEC state follows
    // the peer's wire data and must not subscribe to the local TX tuner.
    let receive_batch = AutoTuneBoundsV2::default().maximum_receive_batch;
    let mut repair_tick = tokio::time::interval(Duration::from_millis(10));
    repair_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_tick = tokio::time::interval(Duration::from_secs(1));
    feedback_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_sequence = 0_u64;
    loop {
        enum Event {
            Cells(Result<Vec<Bytes>>),
            Repair(Option<RepairResponseV2>),
            Tick,
            Feedback,
        }
        let event = tokio::select! {
            datagrams = rx.receive_datagram_batch(receive_batch) => Event::Cells(datagrams),
            response = repaired.recv() => Event::Repair(response),
            _ = repair_tick.tick() => Event::Tick,
            _ = feedback_tick.tick() => Event::Feedback,
        };
        let output = match event {
            Event::Cells(datagrams) => {
                let evicted = apply_receive_buffer_target(&mut rx, &metrics)?;
                if evicted != 0 {
                    warn!(
                        evicted,
                        receive_buffer_bytes = rx.maximum_buffered_bytes(),
                        "evicted stale V2 RX state while shrinking automatic budget"
                    );
                }
                let mut combined = ReassemblyOutput::default();
                for bytes in datagrams? {
                    if CoverPaddingV2::is_record(&bytes) {
                        let length = bytes.len();
                        if let Err(error) = rx.accept_datagram(bytes) {
                            let (errors, report) = metrics.record_protocol_datagram_error();
                            if report {
                                warn!(
                                    errors,
                                    stage = "cover",
                                    %error,
                                    "dropped malformed V2 DATAGRAM; further errors are exponentially sampled"
                                );
                            }
                            continue;
                        }
                        metrics
                            .cover_rx_bytes
                            .fetch_add(length as u64, Ordering::Relaxed);
                        continue;
                    }
                    let disposition = match route.snapshot.dispatch_cell(route.incoming, bytes) {
                        Ok(disposition) => disposition,
                        Err(error) => {
                            let (errors, report) = metrics.record_protocol_datagram_error();
                            if report {
                                warn!(
                                    errors,
                                    stage = "cell-route",
                                    %error,
                                    "dropped malformed V2 DATAGRAM; further errors are exponentially sampled"
                                );
                            }
                            continue;
                        }
                    };
                    match disposition {
                        TransitDispositionV2::Local { header, cell } => {
                            let output = match rx.accept_routed_datagram(cell, header) {
                                Ok(output) => output,
                                Err(error) => {
                                    let (errors, report) = metrics.record_protocol_datagram_error();
                                    if report {
                                        warn!(
                                            errors,
                                            stage = "cell-payload",
                                            %error,
                                            "dropped malformed V2 DATAGRAM; further errors are exponentially sampled"
                                        );
                                    }
                                    continue;
                                }
                            };
                            metrics.observe_receive(&output);
                            combined.merge(output);
                        }
                        TransitDispositionV2::Drop(reason) => {
                            let (drops, report) = metrics.record_route_gate_drop();
                            if report {
                                warn!(
                                    ?reason,
                                    drops,
                                    "dropped V2 Cell at route-label gate; further drops are exponentially sampled"
                                );
                            }
                        }
                        TransitDispositionV2::Forward { .. } => {
                            bail!("single-peer V2 runtime received a transit Cell")
                        }
                        TransitDispositionV2::TtlExpired(_) => {
                            bail!("single-peer V2 runtime produced transit TTL OAM")
                        }
                    }
                }
                Some(combined)
            }
            Event::Repair(Some(response)) => {
                let evicted = apply_receive_buffer_target(&mut rx, &metrics)?;
                if evicted != 0 {
                    warn!(
                        evicted,
                        receive_buffer_bytes = rx.maximum_buffered_bytes(),
                        "evicted stale V2 RX state while shrinking automatic budget"
                    );
                }
                let request_id = response.request_id;
                let route_epoch = response.key.session_epoch;
                match rx.accept_repair_response_at(response, Instant::now())? {
                    Some((output, observation)) => {
                        metrics.observe_repair_response(observation);
                        metrics.observe_receive(&output);
                        Some(output)
                    }
                    None => {
                        let (stale, report) =
                            increment_sampled_counter(&metrics.repair_stale_responses);
                        if report {
                            warn!(
                                request_id,
                                route_epoch,
                                stale,
                                "ignored unmatched or expired V2 Repair response; further events are exponentially sampled"
                            );
                        }
                        None
                    }
                }
            }
            Event::Repair(None) => bail!("V2 Repair control receiver stopped"),
            Event::Tick => {
                let repair_batch = rx.repair_requests_bounded(
                    Instant::now(),
                    adaptive_repair_minimum_age(&metrics),
                    MAX_REPAIR_REQUESTS_PER_TICK,
                );
                metrics.observe_repair_suppression(&repair_batch);
                for request in repair_batch.requests {
                    metrics.observe_repair_request(&request);
                    control
                        .send(TxControl::Send(request.encode()?))
                        .await
                        .context("V2 TX control task stopped")?;
                }
                None
            }
            Event::Feedback => {
                feedback_sequence = feedback_sequence.wrapping_add(1).max(1);
                control
                    .send(TxControl::Send(
                        metrics.fec_feedback(feedback_sequence).encode()?,
                    ))
                    .await
                    .context("V2 TX control task stopped before FEC feedback")?;
                None
            }
        };
        if let Some(output) = output {
            write_reassembled(&mut writer, &metrics, output).await?;
        }
    }
}

pub(super) async fn write_reassembled(
    writer: &mut crate::tunnel::OverlayTunnelWriter,
    metrics: &RuntimeMetrics,
    output: ReassemblyOutput,
) -> Result<()> {
    if output.records.is_empty() {
        return Ok(());
    }
    let count = output.records.len();
    let bytes = output.records.iter().fold(0_u64, |total, record| {
        total.saturating_add(u64::try_from(record.total_len).unwrap_or(u64::MAX))
    });
    let mut ordinary = Vec::new();
    let mut offloaded = Vec::new();
    for record in output.records {
        if record.metadata.is_empty() {
            ordinary.push(completed_record_to_tun(record)?);
        } else {
            let header = crate::protocol::v2::gso::virtio_header_for_record_fragments(
                record.metadata,
                record.total_len,
                &record.fragments,
            )?;
            offloaded.push((header, record.fragments));
        }
    }
    if !ordinary.is_empty() {
        for record in &ordinary {
            if let Some((kind, sequence)) = icmpv4_echo_probe(&record[VIRTIO_NET_HDR_LEN..]) {
                tracing::trace!(
                    target: "ironet::latency_probe",
                    stage = "tun-write",
                    kind,
                    sequence,
                    "V2 ICMP latency probe"
                );
            }
        }
        writer
            .send_owned(0, &mut ordinary)
            .await
            .context("batch-writing ordinary V2 TUN records")?;
    }
    if !offloaded.is_empty() {
        for (header, fragments) in offloaded {
            writer
                .send_raw_vectored(0, &header, &fragments)
                .await
                .context("gather-writing restored V2 offload record")?;
        }
    }
    metrics
        .tun_rx_packets
        .fetch_add(count as u64, Ordering::Relaxed);
    metrics.tun_rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    Ok(())
}

pub(super) async fn control_loop(
    connection: Connection,
    negotiated: crate::protocol::v2::session::NegotiatedSessionV2,
    context: ControlContextV2,
) -> Result<()> {
    let mut receiver = V2ControlRx::new(connection, negotiated);
    loop {
        let record = receiver.receive().await?;
        context.metrics.observe_control_rx(&record);
        if SignedPresenceV2::is_record(&record) {
            context
                .presences
                .send(SignedPresenceV2::decode(record)?)
                .await
                .context("V2 Presence manager stopped")?;
            continue;
        }
        if RouteAdvertisementV2::is_record(&record) {
            context
                .routes
                .send(RouteAdvertisementV2::decode(
                    record,
                    context.allow_default_routes,
                )?)
                .await
                .context("V2 route manager stopped")?;
            continue;
        }
        if FecFeedbackV2::is_record(&record) {
            context
                .metrics
                .apply_remote_feedback(FecFeedbackV2::decode(record)?);
            continue;
        }
        match RepairControlV2::decode(record)? {
            RepairControlV2::Request(request) => context
                .tx
                .send(TxControl::Respond(request))
                .await
                .context("V2 TX control task stopped")?,
            RepairControlV2::Response(response) => context
                .repaired
                .send(response)
                .await
                .context("V2 RX task stopped")?,
        }
    }
}

pub(super) struct PresenceContextV2 {
    pub(super) network_id: String,
    pub(super) local_id: EndpointId,
    pub(super) secret_key: SecretKey,
    pub(super) routes: mpsc::Sender<RouteAdvertisementV2>,
    pub(super) control: mpsc::Sender<TxControl>,
    pub(super) allow_default_routes: bool,
    pub(super) runtime_state: Arc<V2RuntimeState>,
}

pub(super) async fn presence_loop(
    mut local_presence: SignedPresenceV2,
    mut updates: mpsc::Receiver<SignedPresenceV2>,
    context: PresenceContextV2,
) -> Result<()> {
    let PresenceContextV2 {
        network_id,
        local_id,
        secret_key,
        routes,
        control,
        allow_default_routes,
        runtime_state,
    } = context;
    let mut directory = PresenceDirectoryV2::new(network_id.clone())?;
    directory.insert(local_presence.clone(), SystemTime::now())?;
    runtime_state.publish_presence_directory(&directory, 2);
    let mut generation = 1_u64;
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await;
    loop {
        let update = tokio::select! {
            update = updates.recv() => {
                update.context("V2 Presence update channel stopped")?
            }
            _ = refresh.tick() => {
                let now = unix_secs(SystemTime::now())?;
                local_presence.body.sequence = local_presence
                    .body
                    .sequence
                    .checked_add(1)
                    .context("V2 local Presence sequence overflow")?;
                local_presence.body.issued_unix_secs = now;
                local_presence.body.expires_unix_secs = now.saturating_add(180);
                local_presence = SignedPresenceV2::sign(
                    local_presence.body.clone(),
                    &secret_key,
                    &network_id,
                )?;
                control
                    .send(TxControl::Send(local_presence.encode()?))
                    .await
                    .context("V2 TX task stopped before Presence renewal")?;
                local_presence.clone()
            }
        };
        let owner = update.body.owner;
        let result = directory.insert(update, SystemTime::now())?;
        if matches!(
            result,
            PresenceUpdateV2::Duplicate | PresenceUpdateV2::Stale
        ) {
            continue;
        }
        if result == PresenceUpdateV2::Renewed {
            runtime_state.publish_presence_directory(&directory, 2);
            debug!(%owner, "accepted V2 Presence lease renewal without route epoch churn");
            continue;
        }
        generation = generation.wrapping_add(1).max(2);
        let route_epoch = u32::try_from(generation).unwrap_or_else(|_| (generation as u32).max(1));
        let topology = directory.compile_topology(
            generation,
            route_epoch,
            allow_default_routes,
            SystemTime::now(),
        )?;
        let local = topology
            .snapshot(crate::protocol::v2::routing::NodeIdV2(*local_id.as_bytes()))
            .context("compiled V2 Presence topology omitted the local node")?;
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
                generation,
                prefixes: learned_prefixes,
            })
            .await
            .context("V2 route manager stopped")?;
        runtime_state.publish_presence_directory(&directory, 2);
        info!(
            %owner,
            ?result,
            generation,
            nodes = directory.len(),
            routes = local.route_count(),
            labels = local.label_count(),
            "compiled authenticated V2 Presence topology"
        );
    }
}

pub(super) async fn route_loop(
    policy: Arc<KernelRoutePolicyV2>,
    static_routes: Vec<IpNet>,
    mut updates: mpsc::Receiver<RouteAdvertisementV2>,
    runtime_state: Arc<V2RuntimeState>,
) -> Result<()> {
    let mut generation = 0_u64;
    let mut installed = Vec::<IpNet>::new();
    while let Some(update) = updates.recv().await {
        if update.generation < generation {
            warn!(
                received = update.generation,
                current = generation,
                "ignored stale V2 route advertisement"
            );
            continue;
        }
        let desired = update
            .prefixes
            .into_iter()
            .filter(|prefix| !static_routes.contains(prefix))
            .collect::<Vec<_>>();
        if update.generation == generation {
            if desired != installed {
                warn!(generation, "ignored conflicting V2 route generation replay");
            }
            continue;
        }
        for prefix in installed.iter().filter(|prefix| !desired.contains(prefix)) {
            policy.delete_route(*prefix)?;
        }
        for prefix in &desired {
            policy.replace_route(*prefix)?;
        }
        generation = update.generation;
        installed = desired;
        runtime_state.publish_routes(static_routes.iter().chain(&installed).copied());
        info!(
            generation,
            routes = installed.len(),
            "applied authenticated V2 routes"
        );
    }
    bail!("V2 route update channel stopped")
}

pub(super) fn unix_secs(now: SystemTime) -> Result<u64> {
    now.duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")
        .map(|duration| duration.as_secs())
}

pub(super) fn flow_id(key: FlowKey) -> u64 {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    hasher.finish().max(1)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, atomic::Ordering},
        time::Duration,
    };

    use bytes::Bytes;
    use tokio::sync::Semaphore;

    use super::*;

    fn test_packet_info() -> PacketInfo {
        PacketInfo {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            protocol: 6,
            source_port: Some(40_000),
            destination_port: Some(5201),
            length: 90,
            latency_protected: false,
        }
    }

    #[test]
    fn tun_gso_split_is_bounded_by_mtu_and_admission_pressure() {
        const MTU: u16 = 32 * 1024;
        let at_mtu = VIRTIO_NET_HDR_LEN + usize::from(MTU);
        let tcpv4 = tun_rs::VIRTIO_NET_HDR_GSO_TCPV4;

        assert!(!tun_record_exceeds_mtu(at_mtu, MTU));
        assert!(tun_record_exceeds_mtu(at_mtu + 1, MTU));
        assert!(!should_split_tun_gso_record(at_mtu, MTU, tcpv4, false));
        assert!(should_split_tun_gso_record(at_mtu + 1, MTU, tcpv4, false));
        assert!(should_split_tun_gso_record(at_mtu, MTU, tcpv4, true));
        assert!(!should_split_tun_gso_record(
            at_mtu + 1,
            MTU,
            VIRTIO_NET_HDR_GSO_NONE,
            false
        ));
        assert!(!should_split_tun_gso_record(
            at_mtu,
            MTU,
            VIRTIO_NET_HDR_GSO_NONE,
            true
        ));
    }

    fn tcpv4_gso_packet(payload_len: usize, tcp_flags: u8) -> Vec<u8> {
        const IP_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;
        let packet_len = IP_HEADER_LEN + TCP_HEADER_LEN + payload_len;
        let mut packet = vec![0_u8; packet_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&5_201_u16.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = tcp_flags;
        packet
    }

    #[test]
    fn ecn_tcp_gso_is_normalized_split_and_kept_in_one_lane() {
        const TCP_FIN_ACK: u8 = 0x11;
        let mut packet = tcpv4_gso_packet(3_000, TCP_FIN_ACK);
        let aggregate_info = inspect_ip_packet(&packet).unwrap();
        assert!(aggregate_info.latency_protected);

        let header = VirtioNetHdr {
            flags: 1, // VIRTIO_NET_HDR_F_NEEDS_CSUM
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN,
            hdr_len: 40,
            gso_size: 1_200,
            csum_start: 20,
            csum_offset: 16,
        };
        let normalized = normalized_tun_gso_header(header).unwrap();
        assert_eq!(normalized.gso_type, VIRTIO_NET_HDR_GSO_TCPV4);

        let mut outputs = vec![vec![0_u8; 1_500]; 4];
        let mut sizes = vec![0_usize; outputs.len()];
        let segments =
            gso_split(&mut packet, normalized, &mut outputs, &mut sizes, 0, false).unwrap();
        assert_eq!(segments, 3);

        let independently_classified = outputs
            .iter()
            .zip(&sizes)
            .take(segments)
            .map(|(packet, &len)| inspect_ip_packet(&packet[..len]).unwrap())
            .collect::<Vec<_>>();
        assert!(!independently_classified[0].latency_protected);
        assert!(independently_classified[segments - 1].latency_protected);
        assert!(
            independently_classified
                .into_iter()
                .map(|info| inherit_aggregate_latency_class(info, aggregate_info.latency_protected))
                .all(|info| info.latency_protected)
        );
    }

    #[test]
    fn unsupported_gso_type_is_rejected_and_counted_once() {
        let header = VirtioNetHdr {
            gso_type: 0x7f,
            ..VirtioNetHdr::default()
        };
        assert!(normalized_tun_gso_header(header).is_none());
        assert_eq!(
            normalized_tun_gso_header(VirtioNetHdr {
                gso_type: VIRTIO_NET_HDR_GSO_TCPV6 | VIRTIO_NET_HDR_GSO_ECN,
                ..VirtioNetHdr::default()
            })
            .unwrap()
            .gso_type,
            VIRTIO_NET_HDR_GSO_TCPV6
        );

        let metrics = RuntimeMetrics::default();
        record_invalid_tun_gso_type(&metrics, 65_535, header.gso_type);
        assert_eq!(metrics.protocol_datagram_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn reader_gso_split_metrics_fill_the_pre_admission_observation_gap() {
        let observation = tun_gso_fallback_observation(60_000);
        let record = TunIngressRecordV2::priority(Bytes::new(), test_packet_info())
            .with_gso_observation(observation);
        let mut batch = TunIngressBatchV2::default();
        batch.observe(1_200, record.gso);
        let metrics = RuntimeMetrics::default();
        metrics.observe_tun_ingress_batch(batch);
        assert_eq!(metrics.gso_input_bytes.load(Ordering::Relaxed), 60_000);
        assert_eq!(metrics.gso_preserved_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.gso_fallback_splits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn split_gso_observation_follows_the_first_successful_regular_admission() {
        let budget = Arc::new(Semaphore::new(100));
        let held = budget.clone().try_acquire_many_owned(100).unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let metrics = RuntimeMetrics::default();
        let observation = tun_gso_fallback_observation(60_000);

        assert!(
            !try_admit_regular_tun_record_observed(
                &sender,
                &budget,
                Bytes::from(vec![1; 100]),
                test_packet_info(),
                observation,
                &metrics,
            )
            .unwrap()
        );
        drop(held);
        assert!(
            try_admit_regular_tun_record_observed(
                &sender,
                &budget,
                Bytes::from(vec![2; 100]),
                test_packet_info(),
                observation,
                &metrics,
            )
            .unwrap()
        );
        assert_eq!(receiver.try_recv().unwrap().gso, observation);
    }

    #[test]
    fn merge_burst_budget_does_not_raise_per_adjacency_scheduler_watermarks() {
        assert_eq!(crate::v2_runtime::TUN_REGULAR_INPUT_BYTES, 512 * 1024);
        assert_eq!(TX_BULK_ADMISSION_HIGH_WATER_BYTES, 512 * 1024);
        assert_eq!(TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES, 512 * 1024);
    }

    #[test]
    fn repair_wait_policy_scales_the_adaptive_minimum_age() {
        let metrics = RuntimeMetrics::default();
        metrics
            .repair_minimum_age_micros
            .store(200_000, Ordering::Relaxed);
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_millis(200)
        );
        metrics.repair_wait_policy.store(
            RepairWaitPolicyV2::Eager.to_metrics_code(),
            Ordering::Relaxed,
        );
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_millis(100)
        );
        metrics.repair_wait_policy.store(
            RepairWaitPolicyV2::AfterFecWindow.to_metrics_code(),
            Ordering::Relaxed,
        );
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_millis(200)
        );
        metrics.repair_wait_policy.store(
            RepairWaitPolicyV2::Patient.to_metrics_code(),
            Ordering::Relaxed,
        );
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_millis(400)
        );
        // Patient is capped so Repair stays responsive after migration.
        metrics
            .repair_minimum_age_micros
            .store(1_000_000, Ordering::Relaxed);
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_secs(2)
        );
        // Unknown codes degrade to the host default.
        metrics.repair_wait_policy.store(99, Ordering::Relaxed);
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn admission_batch_preserves_records_and_obeys_both_bounds() {
        let mut pending = VecDeque::from([
            TunIngressRecordV2::priority(Bytes::from(vec![1; 100]), test_packet_info()),
            TunIngressRecordV2::priority(Bytes::from(vec![2; 100]), test_packet_info()),
            TunIngressRecordV2::priority(Bytes::from(vec![3; 100]), test_packet_info()),
        ]);
        let first = drain_tun_ingress_batch(&mut pending, 8, 210);
        assert_eq!(first.len(), 2);
        assert_eq!(
            first.iter().map(TunIngressRecordV2::len).sum::<usize>(),
            200
        );
        assert_eq!(pending.len(), 1);

        let second = drain_tun_ingress_batch(&mut pending, 1, 0);
        assert_eq!(second.len(), 1, "the head record must always make progress");
        assert!(pending.is_empty());
    }

    #[test]
    fn tun_ingress_byte_budget_is_held_until_dispatch_consumes_records() {
        let budget = Arc::new(Semaphore::new(200));
        let mut pending = VecDeque::from([
            TunIngressRecordV2::regular(
                Bytes::from(vec![1; 100]),
                test_packet_info(),
                budget.clone().try_acquire_many_owned(100).unwrap(),
            ),
            TunIngressRecordV2::regular(
                Bytes::from(vec![2; 100]),
                test_packet_info(),
                budget.clone().try_acquire_many_owned(100).unwrap(),
            ),
        ]);
        assert_eq!(budget.available_permits(), 0);
        assert!(budget.clone().try_acquire_owned().is_err());

        let first = drain_tun_ingress_batch(&mut pending, 1, 100);
        assert_eq!(first.len(), 1);
        assert_eq!(budget.available_permits(), 0);
        assert_eq!(pending.len(), 1);

        drop(first);
        assert_eq!(budget.available_permits(), 100);
        let second = drain_tun_ingress_batch(&mut pending, 1, 100);
        assert_eq!(second.len(), 1);
        assert_eq!(budget.available_permits(), 100);
        drop(second);
        assert_eq!(budget.available_permits(), 200);
    }

    #[test]
    fn regular_tun_admission_sheds_overload_without_blocking_priority_reads() {
        let budget = Arc::new(Semaphore::new(100));
        let held = budget.clone().try_acquire_many_owned(100).unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let metrics = RuntimeMetrics::default();
        try_admit_regular_tun_record(
            &sender,
            &budget,
            Bytes::from(vec![1; 100]),
            test_packet_info(),
            &metrics,
        )
        .unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(
            metrics.tun_admission_drop_records.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.tun_admission_drop_bytes.load(Ordering::Relaxed),
            100
        );

        drop(held);
        try_admit_regular_tun_record(
            &sender,
            &budget,
            Bytes::from(vec![2; 100]),
            test_packet_info(),
            &metrics,
        )
        .unwrap();
        let admitted = receiver.try_recv().unwrap();
        assert_eq!(budget.available_permits(), 0);
        drop(admitted);
        assert_eq!(budget.available_permits(), 100);
    }

    #[test]
    fn priority_ready_race_forces_a_send_after_each_priority_admission() {
        let mut arbiter = PrioritySendArbiterV2::default();
        for _ in 0..8 {
            assert_eq!(arbiter.next(), PrioritySendTurnV2::PriorityAdmission);
            arbiter.admitted_priority();
            assert_eq!(arbiter.next(), PrioritySendTurnV2::Send);
            for _ in 0..MAX_SENDS_BETWEEN_PRIORITY_ADMISSIONS {
                arbiter.completed_send();
            }
        }
    }

    #[test]
    fn send_ready_race_forces_a_priority_admission_after_a_bounded_send_burst() {
        let mut arbiter = PrioritySendArbiterV2::default();
        arbiter.admitted_priority();
        let sends_before_boundary = MAX_SENDS_BETWEEN_PRIORITY_ADMISSIONS.saturating_sub(1);
        for _ in 0..sends_before_boundary {
            assert_eq!(arbiter.next(), PrioritySendTurnV2::Send);
            arbiter.completed_send();
        }
        assert_eq!(arbiter.next(), PrioritySendTurnV2::Send);
        arbiter.completed_send();
        assert_eq!(arbiter.next(), PrioritySendTurnV2::PriorityAdmission);
    }

    #[test]
    fn ingress_ready_order_preserves_priority_and_regular_ready_races() {
        assert_eq!(
            ingress_ready_order(true, PrioritySendTurnV2::PriorityAdmission),
            IngressReadyOrderV2::PriorityThenSend
        );
        assert_eq!(
            ingress_ready_order(true, PrioritySendTurnV2::Send),
            IngressReadyOrderV2::SendThenPriority
        );
        assert_eq!(
            ingress_ready_order(false, PrioritySendTurnV2::PriorityAdmission),
            IngressReadyOrderV2::PriorityThenSendThenRegular
        );
        assert_eq!(
            ingress_ready_order(false, PrioritySendTurnV2::Send),
            IngressReadyOrderV2::SendThenPriorityThenRegular
        );
    }

    #[tokio::test]
    async fn priority_turn_polls_a_ready_send_before_regular_ingress() {
        let (_priority_sender, mut priority) = mpsc::channel::<()>(1);
        let (regular_sender, mut regular) = mpsc::channel(1);
        regular_sender.send(()).await.unwrap();

        assert_eq!(
            ingress_ready_order(false, PrioritySendTurnV2::PriorityAdmission),
            IngressReadyOrderV2::PriorityThenSendThenRegular
        );
        let selected = tokio::select! {
            biased;
            _ = priority.recv() => "priority",
            _ = std::future::ready(()) => "send",
            _ = regular.recv() => "regular",
        };
        assert_eq!(selected, "send");
        assert_eq!(regular.try_recv(), Ok(()));
    }

    #[test]
    fn repair_grace_tracks_rtt_with_conservative_bounds() {
        assert_eq!(
            repair_minimum_age_for_rtt(Duration::from_millis(1)),
            Duration::from_millis(50)
        );
        assert_eq!(
            repair_minimum_age_for_rtt(Duration::from_millis(13)),
            Duration::from_millis(104)
        );
        assert_eq!(
            repair_minimum_age_for_rtt(Duration::from_secs(1)),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn mixed_scheduler_depth_respects_the_shared_application_watermark() {
        use crate::protocol::v2::scheduler::{SchedulerDepth, SchedulerLimits};

        let application_headroom = SchedulerLimits::default()
            .application_bytes
            .saturating_sub(TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES);
        let maximum_fec_expanded_batch = TX_ADMISSION_BATCH_BYTES
            .saturating_add(RAW_TUN_BYTES)
            .saturating_mul(3)
            / 2;
        assert!(
            application_headroom >= maximum_fec_expanded_batch.saturating_add(64 * 1024),
            "shared headroom must cover one overshooting GSO record, strongest automatic FEC, and Cell envelopes"
        );

        let mixed = SchedulerDepth {
            bulk_bytes: TX_BULK_ADMISSION_HIGH_WATER_BYTES - 64 * 1024,
            latency_bytes: 96 * 1024,
            ..SchedulerDepth::default()
        };
        assert!(
            mixed.bulk_bytes < TX_BULK_ADMISSION_HIGH_WATER_BYTES
                && mixed.latency_bytes < TX_LATENCY_ADMISSION_HIGH_WATER_BYTES
        );
        assert!(
            admission_saturated(mixed, TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES),
            "the shared queue must retain room for one complete TUN admission burst"
        );

        let latency_watermark = SchedulerDepth {
            bulk_bytes: TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES
                - TX_LATENCY_ADMISSION_HIGH_WATER_BYTES
                - 1,
            latency_bytes: TX_LATENCY_ADMISSION_HIGH_WATER_BYTES,
            ..SchedulerDepth::default()
        };
        assert!(admission_saturated(
            latency_watermark,
            TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES
        ));

        let below_all_watermarks = SchedulerDepth {
            bulk_bytes: 256 * 1024,
            latency_bytes: 64 * 1024,
            ..SchedulerDepth::default()
        };
        assert!(!admission_saturated(
            below_all_watermarks,
            TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES
        ));
        assert!(admission_saturated(below_all_watermarks, 256 * 1024));
    }
}
