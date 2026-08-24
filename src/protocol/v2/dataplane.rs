use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use bytes::{Bytes, BytesMut};
use iroh::endpoint::{Connection, RecvStream, SendDatagramError, SendStream};
use rustc_hash::FxHashMap;

use super::{
    cell::{
        CellKind, CellRouteHeaderV2, CellV2, DEFAULT_OVERLAY_HOP_LIMIT, RecordSegment, TrafficClass,
    },
    cover::CoverPaddingV2,
    fec::{CellStripeDecoder, CellStripeEncoder, FecGeometryV2, protected_cell_maximum},
    gso::{encode_train_record, restore_tun_record_fragments},
    reassembly::{
        FecReceiveStatsV2, ReassemblyLimits, ReassemblyOutput, ReassemblyTableLimits,
        ReassemblyTableV2,
    },
    repair::{RepairCacheV2, RepairKeyV2, RepairRequestV2, RepairResponseV2},
    routing::{AdjacencyIdV2, ResolvedRouteV2},
    scheduler::{ScheduledWork, SchedulerDepth, SchedulerLimits, SchedulerStats, V2Scheduler},
    session::NegotiatedSessionV2,
    train::{
        SegmentBufferPool, TrainBuildStats, TrainContext, TrainRecord, build_packet_train,
        build_packet_train_pooled,
    },
    tuning::{
        AutoTuneBoundsV2, CoverTrafficProfileV2, INITIAL_SEND_BUFFER_BYTES_V2,
        REPAIR_CACHE_DEFAULT_TTL_V2, TuneDecisionV2,
    },
};

const CONTROL_MAGIC: &[u8; 4] = b"CTV2";
const DEFAULT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_ACTIVE_ROUTE_EPOCHS: usize = 3;
const MAX_PENDING_REPAIR_REQUESTS: usize = 4_096;
pub const MAX_REPAIR_REQUESTS_PER_TICK: usize = 2;
const MAX_BULK_REPAIR_CELLS: usize = 2;
const MAX_LATENCY_REPAIR_CELLS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendProgress {
    pub class: Option<TrafficClass>,
    pub flow_id: Option<u64>,
    pub queue_sojourn_micros: u64,
    pub bulk_preemption: bool,
    pub datagrams: usize,
    pub bytes: usize,
    pub dropped_datagrams: usize,
    pub dropped_bytes: usize,
    pub cover_padding_bytes: usize,
    pub data_cell_datagrams: usize,
    pub data_cell_bytes: usize,
    pub data_cell_payload_bytes: usize,
    pub fec_datagrams: usize,
    pub fec_bytes: usize,
    /// Present once per locally built PacketTrain, even when that train spans
    /// multiple scheduler quanta. Forwarded trains do not claim build work.
    pub train_stats: Option<TrainBuildStats>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardAdmissionV2 {
    Admitted,
    QueueFull,
    PathMtuExceeded {
        header: CellRouteHeaderV2,
        observed_datagram_size: usize,
        maximum_datagram_size: usize,
    },
}

/// Independent reliable-control receiver. Keeping it separate from `V2Rx`
/// allows QUIC DATAGRAM receive/reassembly and Stream Repair to progress in
/// parallel without sharing a mutable receive state machine.
#[derive(Debug)]
pub struct V2ControlRx {
    connection: Connection,
    maximum_record_bytes: usize,
    stream: Option<RecvStream>,
}

impl V2ControlRx {
    pub fn new(connection: Connection, negotiated: NegotiatedSessionV2) -> Self {
        Self {
            connection,
            maximum_record_bytes: negotiated.limits.max_control_size as usize,
            stream: None,
        }
    }

    pub async fn receive(&mut self) -> Result<Bytes> {
        if self.stream.is_none() {
            let mut stream = self
                .connection
                .accept_uni()
                .await
                .context("accepting V2 control stream")?;
            let mut magic = [0_u8; 4];
            stream.read_exact(&mut magic).await?;
            ensure!(&magic == CONTROL_MAGIC, "invalid V2 control stream magic");
            self.stream = Some(stream);
        }
        let stream = self.stream.as_mut().expect("V2 control stream accepted");
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(
            length <= self.maximum_record_bytes,
            "V2 control record exceeds negotiated limit"
        );
        let mut bytes = BytesMut::zeroed(length);
        stream.read_exact(&mut bytes).await?;
        Ok(bytes.freeze())
    }
}

#[derive(Debug)]
struct PendingWork {
    work: ScheduledWork,
    next_cell: usize,
}

/// Single-writer V2 transmit dataplane. PacketTrains stay resumable in the
/// scheduler and only one bounded quantum is submitted to QUIC at a time.
#[derive(Debug)]
pub struct V2Tx {
    connection: Connection,
    adjacency: Option<AdjacencyIdV2>,
    negotiated: NegotiatedSessionV2,
    scheduler: V2Scheduler,
    pending: Option<PendingWork>,
    preempted_bulk: Option<PendingWork>,
    control_stream: Option<SendStream>,
    fec_encoder: Option<CellStripeEncoder>,
    repair_cache: RepairCacheV2,
    segment_pool: SegmentBufferPool,
    train_target_bytes: usize,
    next_train_id: u64,
    next_cover_sequence: u64,
}

fn effective_datagram_maximum(
    live_quic_maximum: usize,
    negotiated_maximum: u16,
    route_maximum: usize,
) -> usize {
    live_quic_maximum
        .min(usize::from(negotiated_maximum))
        .min(route_maximum)
}

#[derive(Debug, Clone, Copy)]
struct TxRouteV2 {
    epoch: u32,
    label: u32,
    hop_limit: u8,
    datagram_maximum: usize,
}

impl V2Tx {
    pub fn new(
        connection: Connection,
        negotiated: NegotiatedSessionV2,
        limits: SchedulerLimits,
    ) -> Result<Self> {
        Self::new_inner(connection, negotiated, limits, None)
    }

    pub fn new_for_adjacency(
        connection: Connection,
        negotiated: NegotiatedSessionV2,
        limits: SchedulerLimits,
        adjacency: AdjacencyIdV2,
    ) -> Result<Self> {
        AdjacencyIdV2::new(adjacency.0)?;
        Self::new_inner(connection, negotiated, limits, Some(adjacency))
    }

    fn new_inner(
        connection: Connection,
        negotiated: NegotiatedSessionV2,
        limits: SchedulerLimits,
        adjacency: Option<AdjacencyIdV2>,
    ) -> Result<Self> {
        ensure!(negotiated.session_epoch != 0, "V2 session is not active");
        let bounds = AutoTuneBoundsV2::default();
        connection.set_datagram_send_buffer_limit(INITIAL_SEND_BUFFER_BYTES_V2.clamp(
            bounds.minimum_socket_buffer_bytes,
            bounds.maximum_socket_buffer_bytes,
        ));
        Ok(Self {
            connection,
            adjacency,
            negotiated,
            scheduler: V2Scheduler::new(limits)?,
            pending: None,
            preempted_bulk: None,
            control_stream: None,
            fec_encoder: None,
            repair_cache: RepairCacheV2::new(REPAIR_CACHE_DEFAULT_TTL_V2, 2 * 1024 * 1024, 4096)?,
            segment_pool: SegmentBufferPool::default(),
            train_target_bytes: (negotiated.limits.max_train_size as usize).min(32 * 1024),
            next_train_id: 1,
            next_cover_sequence: 1,
        })
    }

    pub fn set_fec(&mut self, geometry: Option<FecGeometryV2>) -> Result<()> {
        match (self.fec_encoder.as_mut(), geometry) {
            (Some(encoder), Some(geometry)) => encoder.reconfigure(geometry)?,
            (None, Some(geometry)) => {
                self.fec_encoder = Some(CellStripeEncoder::new(geometry)?);
            }
            (Some(encoder), None) => {
                let geometry = encoder.geometry();
                encoder.reconfigure(FecGeometryV2 {
                    data_cells: geometry.data_cells,
                    parity_cells: 0,
                })?;
            }
            (None, None) => {}
        }
        Ok(())
    }

    pub fn apply_tuning(&mut self, decision: TuneDecisionV2) -> Result<()> {
        self.connection
            .set_datagram_send_buffer_limit(decision.send_buffer_bytes);
        self.set_fec(decision.fec)?;
        self.scheduler
            .set_bulk_quantum_cells(decision.bulk_quantum_cells)?;
        self.train_target_bytes = decision
            .train_target_bytes
            .clamp(1, self.negotiated.limits.max_train_size as usize);
        self.repair_cache.resize(decision.repair_cache_bytes);
        // 0 keeps the host default horizon.
        let retention = if decision.repair_retention_millis == 0 {
            REPAIR_CACHE_DEFAULT_TTL_V2
        } else {
            Duration::from_millis(u64::from(decision.repair_retention_millis))
        };
        self.repair_cache.set_ttl(retention);
        Ok(())
    }

    pub fn datagram_send_buffer_limit(&self) -> usize {
        self.connection.datagram_send_buffer_limit()
    }

    pub fn enqueue_records_auto(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route_label: u32,
        records: impl IntoIterator<Item = TrainRecord>,
    ) -> Result<Vec<u64>> {
        self.enqueue_records_auto_with_hop_limit(
            flow_id,
            class,
            route_label,
            DEFAULT_OVERLAY_HOP_LIMIT,
            records,
        )
    }

    pub fn enqueue_records_auto_with_hop_limit(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route_label: u32,
        overlay_hop_limit: u8,
        records: impl IntoIterator<Item = TrainRecord>,
    ) -> Result<Vec<u64>> {
        self.enqueue_records_auto_with_hop_limit_and_priority(
            flow_id,
            class,
            route_label,
            overlay_hop_limit,
            records,
            false,
        )
    }

    /// Attach a strict local latency tier without expanding the V2 wire class.
    /// Transit hops make their own local scheduling decision; Latency/Bulk
    /// remains the only class carried in a Cell.
    pub fn enqueue_records_auto_with_hop_limit_and_priority(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route_label: u32,
        overlay_hop_limit: u8,
        records: impl IntoIterator<Item = TrainRecord>,
        priority: bool,
    ) -> Result<Vec<u64>> {
        self.enqueue_records_auto_on_epoch(
            flow_id,
            class,
            TxRouteV2 {
                epoch: self.negotiated.session_epoch,
                label: route_label,
                hop_limit: overlay_hop_limit,
                datagram_maximum: self.negotiated.limits.max_datagram_size as usize,
            },
            records,
            priority,
        )
    }

    /// Multi-peer entry point. The compiled route epoch remains unchanged
    /// across transit adjacencies; each QUIC connection authenticates only its
    /// immediate sender.
    pub fn enqueue_routed_records_auto(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route: ResolvedRouteV2,
        overlay_hop_limit: u8,
        records: impl IntoIterator<Item = TrainRecord>,
    ) -> Result<Vec<u64>> {
        self.enqueue_routed_records_auto_with_priority(
            flow_id,
            class,
            route,
            overlay_hop_limit,
            records,
            false,
        )
    }

    pub fn enqueue_routed_records_auto_with_priority(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route: ResolvedRouteV2,
        overlay_hop_limit: u8,
        records: impl IntoIterator<Item = TrainRecord>,
        priority: bool,
    ) -> Result<Vec<u64>> {
        self.validate_routed_adjacency(route)?;
        self.enqueue_records_auto_on_epoch(
            flow_id,
            class,
            TxRouteV2 {
                epoch: route.route_epoch,
                label: route.route_label.0,
                hop_limit: overlay_hop_limit,
                datagram_maximum: route.maximum_datagram_size as usize,
            },
            records,
            priority,
        )
    }

    fn enqueue_records_auto_on_epoch(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route: TxRouteV2,
        records: impl IntoIterator<Item = TrainRecord>,
        priority: bool,
    ) -> Result<Vec<u64>> {
        ensure!(route.epoch != 0, "V2 route epoch zero is reserved");
        ensure!(route.hop_limit != 0, "V2 overlay hop limit is exhausted");
        let mut admitted = Vec::new();
        let mut batch = Vec::new();
        let mut batch_bytes = 0_usize;
        for record in records {
            let bytes = record
                .data
                .len()
                .checked_add(record.metadata.len())
                .context("V2 record byte count overflow")?;
            if !batch.is_empty() && batch_bytes.saturating_add(bytes) > self.train_target_bytes {
                let Some(train_id) = self.enqueue_records_on_epoch(
                    flow_id,
                    class,
                    route,
                    std::mem::take(&mut batch),
                    priority,
                )?
                else {
                    anyhow::bail!(
                        "V2 scheduler rejected PacketTrain after admitting {} trains",
                        admitted.len()
                    );
                };
                admitted.push(train_id);
                batch_bytes = 0;
            }
            batch_bytes = batch_bytes
                .checked_add(bytes)
                .context("V2 PacketTrain target byte overflow")?;
            batch.push(record);
        }
        if !batch.is_empty() {
            let Some(train_id) =
                self.enqueue_records_on_epoch(flow_id, class, route, batch, priority)?
            else {
                anyhow::bail!(
                    "V2 scheduler rejected PacketTrain after admitting {} trains",
                    admitted.len()
                );
            };
            admitted.push(train_id);
        }
        Ok(admitted)
    }

    pub fn enqueue_virtio_records_auto(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route_label: u32,
        records: impl IntoIterator<Item = Bytes>,
    ) -> Result<Vec<u64>> {
        let records = records
            .into_iter()
            .enumerate()
            .map(|(index, raw)| {
                let record_id = u16::try_from(index + 1)
                    .context("too many virtio records in one V2 enqueue batch")?;
                let (metadata, data) = encode_train_record(raw)?;
                Ok(TrainRecord {
                    record_id,
                    metadata,
                    data,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.enqueue_records_auto(flow_id, class, route_label, records)
    }

    pub fn enqueue_records(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route_label: u32,
        records: impl IntoIterator<Item = TrainRecord>,
    ) -> Result<Option<u64>> {
        self.enqueue_records_with_hop_limit(
            flow_id,
            class,
            route_label,
            DEFAULT_OVERLAY_HOP_LIMIT,
            records,
        )
    }

    pub fn enqueue_records_with_hop_limit(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route_label: u32,
        overlay_hop_limit: u8,
        records: impl IntoIterator<Item = TrainRecord>,
    ) -> Result<Option<u64>> {
        self.enqueue_records_on_epoch(
            flow_id,
            class,
            TxRouteV2 {
                epoch: self.negotiated.session_epoch,
                label: route_label,
                hop_limit: overlay_hop_limit,
                datagram_maximum: self.negotiated.limits.max_datagram_size as usize,
            },
            records,
            false,
        )
    }

    pub fn enqueue_routed_records(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route: ResolvedRouteV2,
        overlay_hop_limit: u8,
        records: impl IntoIterator<Item = TrainRecord>,
    ) -> Result<Option<u64>> {
        self.validate_routed_adjacency(route)?;
        self.enqueue_records_on_epoch(
            flow_id,
            class,
            TxRouteV2 {
                epoch: route.route_epoch,
                label: route.route_label.0,
                hop_limit: overlay_hop_limit,
                datagram_maximum: route.maximum_datagram_size as usize,
            },
            records,
            false,
        )
    }

    fn validate_routed_adjacency(&self, route: ResolvedRouteV2) -> Result<()> {
        ensure!(
            self.adjacency == Some(route.adjacency),
            "V2 PacketTrain route does not belong to this adjacency writer"
        );
        Ok(())
    }

    fn enqueue_records_on_epoch(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        route: TxRouteV2,
        records: impl IntoIterator<Item = TrainRecord>,
        priority: bool,
    ) -> Result<Option<u64>> {
        ensure!(route.epoch != 0, "V2 route epoch zero is reserved");
        let records = records.into_iter().collect::<Vec<_>>();
        // The negotiated train limit is an IP payload ownership bound.
        // Per-record metadata is separately bounded by the Cell codec and must
        // not make a legal 65,535-byte GSO super-packet impossible to carry.
        let record_bytes = records.iter().try_fold(0_usize, |total, record| {
            total
                .checked_add(record.data.len())
                .ok_or_else(|| anyhow::anyhow!("V2 PacketTrain byte count overflow"))
        })?;
        ensure!(
            record_bytes <= self.negotiated.limits.max_train_size as usize,
            "V2 PacketTrain exceeds negotiated byte limit"
        );
        let train_id = self.next_train_id;
        self.next_train_id = self.next_train_id.wrapping_add(1).max(1);
        // PMTU may shrink asynchronously. Read the live QUIC limit for every
        // train so no Cell admitted after a path change can be oversized.
        let path_maximum = effective_datagram_maximum(
            self.connection
                .max_datagram_size()
                .context("peer does not support QUIC DATAGRAM")?,
            self.negotiated.limits.max_datagram_size,
            route.datagram_maximum,
        );
        let maximum_datagram_size = match &self.fec_encoder {
            Some(encoder) if encoder.geometry().parity_cells > 0 => {
                protected_cell_maximum(path_maximum, encoder.geometry().data_cells)?
            }
            _ => path_maximum,
        };
        let context = TrainContext {
            class,
            session_epoch: route.epoch,
            route_label: route.label,
            overlay_hop_limit: route.hop_limit,
            train_id,
            maximum_datagram_size,
            maximum_cells: self.negotiated.limits.max_cells_per_train as usize,
        };
        let admitted = if let Some(encoder) = &mut self.fec_encoder
            && encoder.geometry().parity_cells > 0
        {
            let train = build_packet_train(context, records)?;
            let mut train_stats = train.stats;
            let encoded = encoder.encode(train.cells, path_maximum)?;
            train_stats.fec_stripes = encoded
                .stats
                .protected_data_cells
                .checked_div(encoder.geometry().data_cells as u64)
                .unwrap_or_default();
            train_stats.fec_protected_data_cells = encoded.stats.protected_data_cells;
            train_stats.fec_parity_cells = encoded.stats.parity_cells;
            train_stats.fec_encode_copy_bytes = encoded.stats.encode_copy_bytes;
            train_stats.fec_unprotected_tail_cells = encoded.stats.unprotected_tail_cells;
            self.repair_cache.insert(encoded.systematic.clone())?;
            self.scheduler.enqueue_encoded_train_with_scheduling(
                flow_id,
                class,
                train_id,
                encoded.ordered.into_iter().map(|cell| cell.bytes).collect(),
                Some(train_stats),
                None,
                priority,
            )?
        } else {
            let train = build_packet_train_pooled(context, records, &mut self.segment_pool)?;
            self.scheduler.enqueue_train_with_scheduling_pooled(
                flow_id,
                train,
                maximum_datagram_size,
                None,
                priority,
                &mut self.segment_pool,
            )?
        };
        if admitted {
            Ok(Some(train_id))
        } else {
            Ok(None)
        }
    }

    pub fn enqueue_control(&mut self, record: Bytes) -> Result<bool> {
        ensure!(
            record.len() <= self.negotiated.limits.max_control_size as usize,
            "V2 control record exceeds negotiated limit"
        );
        Ok(self.scheduler.enqueue_control(record))
    }

    pub fn enqueue_probe(&mut self, datagram: Bytes) -> bool {
        self.scheduler.enqueue_probe(datagram)
    }

    pub fn enqueue_cover_padding(&mut self, profile: CoverTrafficProfileV2) -> Result<bool> {
        let (padding, target, maximum) = self.next_cover_padding(profile)?;
        let admitted = self
            .scheduler
            .enqueue_probe(padding.encode(target, maximum)?);
        if admitted {
            self.next_cover_sequence = self.next_cover_sequence.wrapping_add(1).max(1);
        }
        Ok(admitted)
    }

    pub fn cover_padding_target_size(&self, profile: CoverTrafficProfileV2) -> Result<usize> {
        let (padding, _, maximum) = self.next_cover_padding(profile)?;
        Ok(padding.target_size(maximum))
    }

    fn next_cover_padding(
        &self,
        profile: CoverTrafficProfileV2,
    ) -> Result<(CoverPaddingV2, usize, usize)> {
        let maximum = self
            .connection
            .max_datagram_size()
            .context("peer does not support QUIC DATAGRAM")?
            .min(self.negotiated.limits.max_datagram_size.into());
        let padding = CoverPaddingV2 {
            profile,
            session_epoch: self.negotiated.session_epoch,
            sequence: self.next_cover_sequence,
        };
        let target = padding.target_size(maximum);
        Ok((padding, target, maximum))
    }

    /// Admit an already encoded Cell selected by the immutable transit label
    /// table. The fixed routing shim was advanced by the caller; this writer
    /// neither decodes Records nor re-applies FEC.
    pub fn admit_forwarded_cells(
        &mut self,
        flow_id: u64,
        cells: Vec<Bytes>,
    ) -> Result<ForwardAdmissionV2> {
        ensure!(
            self.adjacency.is_some(),
            "V2 transit Cell requires an adjacency-bound writer"
        );
        ensure!(!cells.is_empty(), "V2 transit Cell batch is empty");
        let maximum = self
            .connection
            .max_datagram_size()
            .context("peer does not support QUIC DATAGRAM")?
            .min(self.negotiated.limits.max_datagram_size.into());
        let largest = cells.iter().map(Bytes::len).max().unwrap_or_default();
        if largest > maximum {
            let offending = cells
                .iter()
                .find(|cell| cell.len() > maximum)
                .expect("largest forwarded Cell exceeds PMTU");
            return Ok(ForwardAdmissionV2::PathMtuExceeded {
                header: CellRouteHeaderV2::decode(offending)?,
                observed_datagram_size: offending.len(),
                maximum_datagram_size: maximum,
            });
        }
        Ok(if self.scheduler.enqueue_forwarded_cells(flow_id, cells)? {
            ForwardAdmissionV2::Admitted
        } else {
            ForwardAdmissionV2::QueueFull
        })
    }

    pub fn enqueue_forwarded_cells(&mut self, flow_id: u64, cells: Vec<Bytes>) -> Result<bool> {
        match self.admit_forwarded_cells(flow_id, cells)? {
            ForwardAdmissionV2::Admitted => Ok(true),
            ForwardAdmissionV2::QueueFull => Ok(false),
            ForwardAdmissionV2::PathMtuExceeded {
                observed_datagram_size,
                maximum_datagram_size,
                ..
            } => bail!(
                "V2 transit Cell ({observed_datagram_size} bytes) exceeds live adjacency PMTU ({maximum_datagram_size} bytes)"
            ),
        }
    }

    pub fn enqueue_forwarded_cell(&mut self, flow_id: u64, cell: Bytes) -> Result<bool> {
        self.enqueue_forwarded_cells(flow_id, vec![cell])
    }

    pub fn repair_response(&mut self, request: &RepairRequestV2) -> RepairResponseV2 {
        self.repair_cache.respond(request)
    }

    pub fn handle_repair_request(&mut self, record: Bytes) -> Result<bool> {
        let request = RepairRequestV2::decode(record)?;
        let response = self.repair_response(&request).encode()?;
        self.enqueue_control(response)
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
            || self.preempted_bulk.is_some()
            || !depth_is_empty(self.scheduler.depth())
    }

    pub fn depth(&self) -> SchedulerDepth {
        self.scheduler.depth()
    }

    pub fn stats(&self) -> SchedulerStats {
        self.scheduler.stats()
    }

    /// Sends at most one scheduler quantum. A Cell quantum is admitted through
    /// one batched QUIC operation, amortizing its connection-state lock.
    pub async fn send_next(&mut self) -> Result<Option<SendProgress>> {
        // `tokio::select!` may cancel an ordinary send while it is waiting for
        // the driver-owned DATAGRAM mailbox. The selected scheduler quantum
        // remains in `pending`; without this swap, newly admitted latency work
        // cannot run until that old Bulk admission eventually succeeds. Keep
        // the interrupted quantum intact and recheck the hierarchy before
        // every asynchronous admission attempt.
        if self.preempted_bulk.is_none()
            && self.scheduler.has_strict_urgent()
            && self.pending.as_ref().is_some_and(|pending| {
                matches!(
                    &pending.work,
                    ScheduledWork::Cells(quantum)
                        if quantum.class == TrafficClass::Bulk && !quantum.priority
                )
            })
        {
            self.preempted_bulk = self.pending.take();
        }
        if self.pending.is_none() {
            self.pending = if self.scheduler.has_strict_urgent() {
                self.scheduler
                    .pop()
                    .map(|work| PendingWork { work, next_cell: 0 })
            } else {
                self.preempted_bulk.take().or_else(|| {
                    self.scheduler
                        .pop()
                        .map(|work| PendingWork { work, next_cell: 0 })
                })
            };
        }
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        let progress = match &pending.work {
            ScheduledWork::Control(record) => {
                if self.control_stream.is_none() {
                    let mut stream = self
                        .connection
                        .open_uni()
                        .await
                        .context("opening V2 control stream")?;
                    stream.write_all(CONTROL_MAGIC).await?;
                    self.control_stream = Some(stream);
                }
                let stream = self
                    .control_stream
                    .as_mut()
                    .expect("V2 control stream was opened");
                stream
                    .write_all(&(record.len() as u32).to_be_bytes())
                    .await?;
                stream.write_all(record).await?;
                SendProgress {
                    class: None,
                    flow_id: None,
                    queue_sojourn_micros: 0,
                    bulk_preemption: false,
                    datagrams: 0,
                    bytes: record.len(),
                    dropped_datagrams: 0,
                    dropped_bytes: 0,
                    cover_padding_bytes: 0,
                    data_cell_datagrams: 0,
                    data_cell_bytes: 0,
                    data_cell_payload_bytes: 0,
                    fec_datagrams: 0,
                    fec_bytes: 0,
                    train_stats: None,
                }
            }
            ScheduledWork::Probe(datagram) => {
                let live_maximum = self.connection.max_datagram_size().unwrap_or_default();
                let sent = if datagram.len() > live_maximum {
                    false
                } else {
                    match self.connection.send_datagram_wait(datagram.clone()).await {
                        Ok(()) => true,
                        // Cover/probe traffic is explicitly lowest priority
                        // and unreliable. A PMTU race must retire it rather
                        // than terminate the authenticated V2 session.
                        Err(SendDatagramError::TooLarge) => false,
                        Err(error) => {
                            return Err(anyhow::anyhow!(
                                "sending V2 probe DATAGRAM failed: {error}"
                            ));
                        }
                    }
                };
                if sent {
                    SendProgress {
                        class: None,
                        flow_id: None,
                        queue_sojourn_micros: 0,
                        bulk_preemption: false,
                        datagrams: 1,
                        bytes: datagram.len(),
                        dropped_datagrams: 0,
                        dropped_bytes: 0,
                        cover_padding_bytes: datagram.len(),
                        data_cell_datagrams: 0,
                        data_cell_bytes: 0,
                        data_cell_payload_bytes: 0,
                        fec_datagrams: 0,
                        fec_bytes: 0,
                        train_stats: None,
                    }
                } else {
                    SendProgress {
                        class: None,
                        flow_id: None,
                        queue_sojourn_micros: 0,
                        bulk_preemption: false,
                        datagrams: 0,
                        bytes: 0,
                        dropped_datagrams: 1,
                        dropped_bytes: datagram.len(),
                        cover_padding_bytes: 0,
                        data_cell_datagrams: 0,
                        data_cell_bytes: 0,
                        data_cell_payload_bytes: 0,
                        fec_datagrams: 0,
                        fec_bytes: 0,
                        train_stats: None,
                    }
                }
            }
            ScheduledWork::Cells(quantum) => {
                let start = pending.next_cell;
                let live_maximum = self
                    .connection
                    .max_datagram_size()
                    .context("peer stopped supporting QUIC DATAGRAM")?;
                let mut cells = Vec::with_capacity(quantum.cells.len() - start);
                let mut dropped_datagrams = 0;
                let mut dropped_bytes = 0;
                let mut attempted_data_datagrams = 0_usize;
                let mut attempted_data_bytes = 0_usize;
                let mut attempted_data_payload_bytes = 0_usize;
                let mut attempted_fec_datagrams = 0_usize;
                let mut attempted_fec_bytes = 0_usize;
                for cell in &quantum.cells[start..] {
                    if cell.len() <= live_maximum {
                        if cell.header.kind == CellKind::FecParity {
                            attempted_fec_datagrams += 1;
                            attempted_fec_bytes += cell.len();
                        } else {
                            debug_assert_eq!(cell.header.kind, CellKind::Data);
                            attempted_data_datagrams += 1;
                            attempted_data_bytes += cell.len();
                            attempted_data_payload_bytes += usize::from(cell.header.payload_len);
                        }
                        cells.push(cell.payload.clone());
                    } else {
                        dropped_datagrams += 1;
                        dropped_bytes += cell.len();
                    }
                }
                let attempted_datagrams = cells.len();
                let attempted_bytes = cells.iter().map(|cell| cell.len()).sum::<usize>();
                let (datagrams, bytes) = if cells.is_empty() {
                    (0, 0)
                } else {
                    if quantum.priority {
                        tracing::trace!(
                            target: "ironet::latency_probe",
                            stage = "quic-admit",
                            flow_id = quantum.flow_id,
                            sojourn_micros = quantum.sojourn.as_micros() as u64,
                            datagrams = cells.len(),
                            "V2 strict latency quantum"
                        );
                    }
                    let result = if quantum.priority {
                        self.connection
                            .send_datagram_payload_batch_buffered_priority(cells)
                            .await
                    } else {
                        self.connection
                            .send_datagram_payload_batch_buffered(cells)
                            .await
                    };
                    match result {
                        Ok(()) => (attempted_datagrams, attempted_bytes),
                        // PMTU may shrink between the lock-free maximum read
                        // and QUIC admission. DATAGRAM is explicitly lossy;
                        // retire this bounded quantum and let subsequent
                        // PacketTrains rebuild at the new live maximum rather
                        // than terminating the authenticated session.
                        Err(SendDatagramError::TooLarge) => {
                            dropped_datagrams += attempted_datagrams;
                            dropped_bytes += attempted_bytes;
                            (0, 0)
                        }
                        Err(error) => {
                            return Err(anyhow::anyhow!(
                                "sending V2 Cell DATAGRAM batch failed: {error}"
                            ));
                        }
                    }
                };
                pending.next_cell = quantum.cells.len();
                let sent = datagrams != 0;
                SendProgress {
                    class: Some(quantum.class),
                    flow_id: Some(quantum.flow_id),
                    queue_sojourn_micros: quantum.sojourn.as_micros().min(u128::from(u64::MAX))
                        as u64,
                    bulk_preemption: quantum.bulk_preemption,
                    datagrams,
                    bytes,
                    dropped_datagrams,
                    dropped_bytes,
                    cover_padding_bytes: 0,
                    data_cell_datagrams: if sent { attempted_data_datagrams } else { 0 },
                    data_cell_bytes: if sent { attempted_data_bytes } else { 0 },
                    data_cell_payload_bytes: if sent {
                        attempted_data_payload_bytes
                    } else {
                        0
                    },
                    fec_datagrams: if sent { attempted_fec_datagrams } else { 0 },
                    fec_bytes: if sent { attempted_fec_bytes } else { 0 },
                    train_stats: quantum.train_stats,
                }
            }
        };
        self.pending = None;
        Ok(Some(progress))
    }
}

impl Drop for V2Tx {
    fn drop(&mut self) {
        if let Some(mut stream) = self.control_stream.take() {
            let _ = stream.finish();
        }
    }
}

/// Single-writer V2 receive dataplane with bounded interleaved-train state.
#[derive(Debug)]
struct RxEpochState {
    reassembly: ReassemblyTableV2,
    fec_decoder: Option<CellStripeDecoder>,
    record_storage: Vec<RecordSegment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairResponseObservationV2 {
    pub requested_cells: u64,
    pub received_cells: u64,
    pub latency_micros: u64,
}

#[derive(Debug, Default)]
pub struct RepairRequestBatchV2 {
    pub requests: Vec<RepairRequestV2>,
    pub suppressed_stripes: u64,
    pub suppressed_cells: u64,
}

#[derive(Debug, Clone, Copy)]
struct PendingRepairRequestV2 {
    key: RepairKeyV2,
    requested_cells: u64,
    requested_at: Instant,
}

/// Bounded request lifecycle table. Repair runs on a reliable QUIC stream,
/// but a response can still arrive after a route generation was retired or a
/// peer reconnected. Matching both the opaque request id and the stripe key
/// prevents such stale control records from injecting Cells into live RX
/// state, while retaining exact request-to-response latency for auto-tuning.
#[derive(Debug)]
struct PendingRepairRequestsV2 {
    capacity: usize,
    ttl: Duration,
    next_request_id: u64,
    entries: FxHashMap<u64, PendingRepairRequestV2>,
    order: VecDeque<(u64, Instant)>,
}

impl PendingRepairRequestsV2 {
    fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity > 0, "V2 pending Repair capacity is zero");
        assert!(!ttl.is_zero(), "V2 pending Repair TTL is zero");
        Self {
            capacity,
            ttl,
            next_request_id: 1,
            entries: FxHashMap::default(),
            order: VecDeque::new(),
        }
    }

    fn begin(&mut self, key: RepairKeyV2, requested_cells: usize, now: Instant) -> u64 {
        self.expire(now);
        while self.entries.len() >= self.capacity {
            if !self.evict_oldest() {
                break;
            }
        }
        let request_id = loop {
            let candidate = self.next_request_id;
            self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
            if !self.entries.contains_key(&candidate) {
                break candidate;
            }
        };
        self.entries.insert(
            request_id,
            PendingRepairRequestV2 {
                key,
                requested_cells: requested_cells as u64,
                requested_at: now,
            },
        );
        self.order.push_back((request_id, now));
        request_id
    }

    fn complete(
        &mut self,
        response: &RepairResponseV2,
        now: Instant,
    ) -> Result<Option<RepairResponseObservationV2>> {
        self.expire(now);
        let Some(pending) = self.entries.get(&response.request_id).copied() else {
            return Ok(None);
        };
        ensure!(
            pending.key == response.key,
            "V2 Repair response key does not match its outstanding request"
        );
        self.entries.remove(&response.request_id);
        Ok(Some(RepairResponseObservationV2 {
            requested_cells: pending.requested_cells,
            received_cells: response.cells.len() as u64,
            latency_micros: now
                .saturating_duration_since(pending.requested_at)
                .as_micros()
                .min(u128::from(u64::MAX)) as u64,
        }))
    }

    fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        while let Some(&(request_id, generation)) = self.order.front() {
            let stale = self.entries.get(&request_id).is_none_or(|pending| {
                pending.requested_at != generation
                    || now.saturating_duration_since(pending.requested_at) >= self.ttl
            });
            if !stale {
                break;
            }
            self.order.pop_front();
            if self
                .entries
                .get(&request_id)
                .is_some_and(|pending| pending.requested_at == generation)
            {
                self.entries.remove(&request_id);
                expired += 1;
            }
        }
        expired
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some((request_id, generation)) = self.order.pop_front() {
            if self
                .entries
                .get(&request_id)
                .is_some_and(|pending| pending.requested_at == generation)
            {
                self.entries.remove(&request_id);
                return true;
            }
        }
        false
    }
}

#[derive(Debug)]
pub struct V2Rx {
    connection: Connection,
    negotiated: NegotiatedSessionV2,
    maximum_buffered_bytes: usize,
    /// Policy-driven aggregate reassembly byte budget (0 = follow
    /// `maximum_buffered_bytes`). Never exceeds the receive buffer, so it can
    /// only shrink the reassembly share.
    reassembly_budget_bytes: usize,
    /// Policy-driven active-train budget (0 = negotiated wire limit).
    active_train_budget: usize,
    epochs: FxHashMap<u32, RxEpochState>,
    epoch_order: VecDeque<u32>,
    fec_enabled: bool,
    fec_ttl: Duration,
    control_stream: Option<RecvStream>,
    pending_repairs: PendingRepairRequestsV2,
}

impl V2Rx {
    pub fn new(
        connection: Connection,
        negotiated: NegotiatedSessionV2,
        maximum_buffered_bytes: usize,
    ) -> Result<Self> {
        let route_epoch = negotiated.session_epoch;
        Self::new_for_route_epoch(connection, negotiated, route_epoch, maximum_buffered_bytes)
    }

    pub fn new_for_route_epoch(
        connection: Connection,
        negotiated: NegotiatedSessionV2,
        route_epoch: u32,
        maximum_buffered_bytes: usize,
    ) -> Result<Self> {
        ensure!(route_epoch != 0, "V2 route epoch zero is reserved");
        ensure!(maximum_buffered_bytes > 0, "V2 receive byte budget is zero");
        let fec_enabled = negotiated.capabilities & super::session::capability::FEC_STRIPES != 0;
        let mut receiver = Self {
            connection,
            negotiated,
            maximum_buffered_bytes,
            reassembly_budget_bytes: 0,
            active_train_budget: 0,
            epochs: FxHashMap::default(),
            epoch_order: VecDeque::new(),
            fec_enabled,
            fec_ttl: DEFAULT_REASSEMBLY_TIMEOUT,
            control_stream: None,
            pending_repairs: PendingRepairRequestsV2::new(
                MAX_PENDING_REPAIR_REQUESTS,
                DEFAULT_REASSEMBLY_TIMEOUT,
            ),
        };
        receiver.activate_route_epoch(route_epoch)?;
        Ok(receiver)
    }

    fn component_budget_bytes(
        maximum_buffered_bytes: usize,
        active_epochs: usize,
    ) -> Result<usize> {
        let active_epochs = active_epochs.clamp(1, MAX_ACTIVE_ROUTE_EPOCHS);
        let component_budget = maximum_buffered_bytes
            .checked_div(active_epochs * 2)
            .context("V2 receive byte budget overflow")?;
        ensure!(
            component_budget >= super::cell::MAX_RECORD_BYTES,
            "V2 receive byte budget is too small"
        );
        Ok(component_budget)
    }

    /// Reassembly's per-epoch share of the component budget under the
    /// policy-driven aggregate budget. Zero budget means reassembly keeps an
    /// even half of the receive buffer; an explicit budget can only shrink
    /// the share below that.
    fn reassembly_share_bytes(&self, component_budget: usize, active_epochs: usize) -> usize {
        if self.reassembly_budget_bytes == 0 {
            component_budget
        } else {
            let active_epochs = active_epochs.clamp(1, MAX_ACTIVE_ROUTE_EPOCHS);
            component_budget.min(self.reassembly_budget_bytes / active_epochs)
        }
    }

    fn active_train_limit(&self) -> usize {
        let negotiated = self.negotiated.limits.max_active_trains as usize;
        if self.active_train_budget == 0 {
            negotiated
        } else {
            self.active_train_budget.min(negotiated)
        }
    }

    fn build_epoch_state(
        &self,
        route_epoch: u32,
        component_budget: usize,
        active_epochs: usize,
    ) -> Result<RxEpochState> {
        // `max_train_size` bounds owned IP payload bytes. Metadata is bounded
        // independently on the wire, so reserve its worst-case contribution
        // rather than rejecting a legal 65,535-byte GSO record at the final
        // fragment merely because it carries virtio metadata.
        let metadata_budget = (self.negotiated.limits.max_cells_per_train as usize)
            .checked_mul(super::cell::MAX_METADATA_BYTES)
            .context("V2 per-train metadata budget overflow")?;
        let per_train_bytes = (self.negotiated.limits.max_train_size as usize)
            .max(self.negotiated.limits.max_record_size as usize)
            .max(super::cell::MAX_RECORD_BYTES)
            .checked_add(metadata_budget)
            .context("V2 per-train receive budget overflow")?;
        let reassembly = ReassemblyTableV2::new(ReassemblyTableLimits {
            session_epoch: route_epoch,
            maximum_active_trains: self.active_train_limit(),
            maximum_buffered_bytes: self.reassembly_share_bytes(component_budget, active_epochs),
            train_timeout: DEFAULT_REASSEMBLY_TIMEOUT,
            per_train: ReassemblyLimits {
                maximum_cells: self.negotiated.limits.max_cells_per_train as usize,
                maximum_active_records: self.negotiated.limits.max_cells_per_train as usize,
                maximum_buffered_bytes: per_train_bytes,
            },
        })?;
        let fec_decoder = self
            .fec_enabled
            .then(|| {
                CellStripeDecoder::with_limits(
                    route_epoch,
                    self.fec_ttl,
                    self.negotiated.limits.max_active_trains as usize,
                    component_budget,
                )
            })
            .transpose()?;
        Ok(RxEpochState {
            reassembly,
            fec_decoder,
            record_storage: Vec::with_capacity(1),
        })
    }

    /// Install a compiled route generation before publishing it to transmit
    /// writers. A small generation window lets in-flight PacketTrains from the
    /// previous immutable snapshots drain without weakening epoch validation.
    pub fn activate_route_epoch(&mut self, route_epoch: u32) -> Result<()> {
        ensure!(route_epoch != 0, "V2 route epoch zero is reserved");
        if self.epochs.contains_key(&route_epoch) {
            return Ok(());
        }
        while self.epochs.len() >= MAX_ACTIVE_ROUTE_EPOCHS {
            let oldest = self
                .epoch_order
                .pop_front()
                .expect("V2 RX epoch order matches state map");
            self.epochs.remove(&oldest);
        }
        let component_budget =
            Self::component_budget_bytes(self.maximum_buffered_bytes, self.epochs.len() + 1)?;
        let state = self.build_epoch_state(route_epoch, component_budget, self.epochs.len() + 1)?;
        self.epochs.insert(route_epoch, state);
        self.epoch_order.push_back(route_epoch);
        self.resize_epoch_components(component_budget)
            .context("rebalancing V2 receive budget after route epoch activation")?;
        Ok(())
    }

    pub fn active_route_epochs(&self) -> impl Iterator<Item = u32> + '_ {
        self.epoch_order.iter().copied()
    }

    /// Apply the negotiated aggregate RX memory target across every retained
    /// route generation without rebuilding the receiver or dropping all
    /// in-flight state at once.
    pub fn set_maximum_buffered_bytes(&mut self, maximum_buffered_bytes: usize) -> Result<usize> {
        let component_budget =
            Self::component_budget_bytes(maximum_buffered_bytes, self.epochs.len())?;
        self.maximum_buffered_bytes = maximum_buffered_bytes;
        self.resize_epoch_components(component_budget)
    }

    fn resize_epoch_components(&mut self, component_budget: usize) -> Result<usize> {
        let reassembly_share = self.reassembly_share_bytes(component_budget, self.epochs.len());
        let train_limit = self.active_train_limit();
        let mut evicted = 0;
        for state in self.epochs.values_mut() {
            evicted += state
                .reassembly
                .set_maximum_buffered_bytes(reassembly_share)?;
            state.reassembly.set_maximum_active_trains(train_limit)?;
            if let Some(decoder) = &mut state.fec_decoder {
                evicted += decoder.set_maximum_buffered_bytes(component_budget)?;
            }
        }
        Ok(evicted)
    }

    /// Apply the policy-driven reassembly budget (aggregate bytes, 0 =
    /// follow the receive buffer) and active-train budget (0 = negotiated
    /// wire limit) across every retained route generation.
    pub fn set_reassembly_budget(
        &mut self,
        budget_bytes: usize,
        active_train_budget: usize,
    ) -> Result<usize> {
        self.reassembly_budget_bytes = budget_bytes;
        self.active_train_budget = active_train_budget;
        let component_budget =
            Self::component_budget_bytes(self.maximum_buffered_bytes, self.epochs.len())?;
        self.resize_epoch_components(component_budget)
    }

    pub fn reassembly_budget_bytes(&self) -> usize {
        self.reassembly_budget_bytes
    }

    pub fn active_train_budget(&self) -> usize {
        self.active_train_budget
    }

    pub fn maximum_buffered_bytes(&self) -> usize {
        self.maximum_buffered_bytes
    }

    pub fn set_fec(&mut self, enabled: bool, ttl: Duration) -> Result<()> {
        ensure!(!ttl.is_zero(), "V2 FEC stripe TTL is zero");
        self.fec_enabled = enabled;
        self.fec_ttl = ttl;
        let component_budget =
            Self::component_budget_bytes(self.maximum_buffered_bytes, self.epochs.len())?;
        for (&route_epoch, state) in &mut self.epochs {
            state.fec_decoder = enabled
                .then(|| {
                    CellStripeDecoder::with_limits(
                        route_epoch,
                        ttl,
                        self.negotiated.limits.max_active_trains as usize,
                        component_budget,
                    )
                })
                .transpose()?;
        }
        Ok(())
    }

    pub fn apply_tuning(&mut self, decision: TuneDecisionV2, ttl: Duration) -> Result<()> {
        self.set_maximum_buffered_bytes(decision.receive_buffer_bytes)?;
        self.set_reassembly_budget(
            decision.reassembly_budget_bytes,
            usize::from(decision.active_train_budget),
        )?;
        if self.negotiated.capabilities & super::session::capability::FEC_STRIPES != 0 {
            ensure!(!ttl.is_zero(), "V2 FEC stripe TTL is zero");
            self.fec_enabled = true;
            self.fec_ttl = ttl;
            let component_budget =
                Self::component_budget_bytes(self.maximum_buffered_bytes, self.epochs.len())?;
            for (&route_epoch, state) in &mut self.epochs {
                if state.fec_decoder.is_none() {
                    state.fec_decoder = Some(CellStripeDecoder::with_limits(
                        route_epoch,
                        ttl,
                        self.negotiated.limits.max_active_trains as usize,
                        component_budget,
                    )?);
                } else if let Some(decoder) = &mut state.fec_decoder {
                    decoder.set_ttl(ttl)?;
                }
            }
        }
        Ok(())
    }

    pub fn repair_requests(&mut self, now: Instant, minimum_age: Duration) -> Vec<RepairRequestV2> {
        self.repair_requests_bounded(now, minimum_age, usize::MAX)
            .requests
    }

    /// Build a bounded, latency-first Repair batch. Large Bulk holes are a
    /// congestion signature rather than a good retransmission candidate: a
    /// reliable response for five or more Cells feeds substantial extra data
    /// into the same saturated QUIC connection and may still arrive after the
    /// inner transport retransmits. Repair therefore closes sparse holes; the
    /// inner transport handles large bursts. Candidates are consumed even
    /// when suppressed so a 10 ms polling loop cannot repeatedly reconsider
    /// and amplify the same stripe.
    pub fn repair_requests_bounded(
        &mut self,
        now: Instant,
        minimum_age: Duration,
        maximum_requests: usize,
    ) -> RepairRequestBatchV2 {
        let epochs = self.epoch_order.iter().copied().collect::<Vec<_>>();
        let mut candidates = Vec::new();
        for epoch in epochs {
            if let Some(decoder) = self
                .epochs
                .get_mut(&epoch)
                .and_then(|state| state.fec_decoder.as_mut())
            {
                candidates.extend(decoder.repair_candidates(now, minimum_age));
            }
        }
        candidates.sort_by_key(|missing| {
            (
                matches!(missing.class, TrafficClass::Bulk),
                missing.missing_sequences.len(),
            )
        });
        let mut batch = RepairRequestBatchV2::default();
        for missing in candidates {
            let cell_limit = match missing.class {
                TrafficClass::Latency => MAX_LATENCY_REPAIR_CELLS,
                TrafficClass::Bulk => MAX_BULK_REPAIR_CELLS,
            };
            if batch.requests.len() >= maximum_requests
                || missing.missing_sequences.len() > cell_limit
            {
                batch.suppressed_stripes = batch.suppressed_stripes.saturating_add(1);
                batch.suppressed_cells = batch
                    .suppressed_cells
                    .saturating_add(missing.missing_sequences.len() as u64);
                continue;
            }
            let key = RepairKeyV2 {
                class: missing.class,
                session_epoch: missing.session_epoch,
                route_label: missing.route_label,
                train_id: missing.train_id,
                stripe_id: missing.stripe_id,
            };
            let request_id = self
                .pending_repairs
                .begin(key, missing.missing_sequences.len(), now);
            batch.requests.push(RepairRequestV2 {
                key,
                request_id,
                missing_sequences: missing.missing_sequences,
            });
        }
        batch
    }

    pub fn accept_repair_response(
        &mut self,
        response: RepairResponseV2,
    ) -> Result<Option<(ReassemblyOutput, RepairResponseObservationV2)>> {
        self.accept_repair_response_at(response, Instant::now())
    }

    pub fn accept_repair_response_at(
        &mut self,
        response: RepairResponseV2,
        now: Instant,
    ) -> Result<Option<(ReassemblyOutput, RepairResponseObservationV2)>> {
        let Some(observation) = self.pending_repairs.complete(&response, now)? else {
            return Ok(None);
        };
        if !self.epochs.contains_key(&response.key.session_epoch) {
            return Ok(None);
        }
        let mut combined = ReassemblyOutput {
            records: Vec::new(),
            duplicate_cell: false,
            train_complete: false,
            pressure_evicted_trains: 0,
            reassembly_expired_trains: 0,
            reorder_cells: 0,
            missing_cells: 0,
            fec: FecReceiveStatsV2::default(),
        };
        for cell in response.cells {
            let output = self.accept_datagram(cell)?;
            combined.merge(output);
        }
        Ok(Some((combined, observation)))
    }

    pub async fn receive_cell(&mut self) -> Result<ReassemblyOutput> {
        let bytes = self.receive_datagram().await?;
        self.accept_datagram(bytes)
    }

    pub async fn receive_datagram(&self) -> Result<Bytes> {
        let bytes = self
            .connection
            .read_datagram()
            .await
            .context("receiving V2 Cell DATAGRAM")?;
        Ok(bytes)
    }

    /// Wait for the first QUIC DATAGRAM and drain the current buffered burst
    /// under one connection-state lock.
    pub async fn receive_datagram_batch(&self, maximum: usize) -> Result<Vec<Bytes>> {
        self.connection
            .read_datagram_batch(maximum)
            .await
            .context("receiving V2 Cell DATAGRAM batch")
    }

    /// Drain already-buffered QUIC DATAGRAMs without another async wakeup.
    /// The caller supplies the tuned hard batch bound, so this operation can
    /// amortize RX state and TUN writes without delaying the first Cell.
    pub fn try_receive_datagram_batch(&self, maximum: usize) -> Result<Vec<Bytes>> {
        self.connection
            .try_read_datagram_batch(maximum)
            .context("draining V2 Cell DATAGRAM batch")
    }

    pub fn accept_datagram(&mut self, bytes: Bytes) -> Result<ReassemblyOutput> {
        ensure!(
            bytes.len() <= self.negotiated.limits.max_datagram_size as usize,
            "V2 DATAGRAM exceeds negotiated limit"
        );
        if CoverPaddingV2::is_record(&bytes) {
            CoverPaddingV2::decode(&bytes, self.negotiated.session_epoch)?;
            return Ok(ReassemblyOutput {
                records: Vec::new(),
                duplicate_cell: false,
                train_complete: false,
                pressure_evicted_trains: 0,
                reassembly_expired_trains: 0,
                reorder_cells: 0,
                missing_cells: 0,
                fec: FecReceiveStatsV2::default(),
            });
        }
        let route_header = CellRouteHeaderV2::decode(&bytes)?;
        self.accept_routed_datagram(bytes, route_header)
    }

    /// Accept a Cell after the immutable route snapshot already parsed and
    /// validated its fixed shim. Local delivery uses this to avoid decoding
    /// the same 36-byte header again in the RX epoch.
    pub(crate) fn accept_routed_datagram(
        &mut self,
        bytes: Bytes,
        route_header: CellRouteHeaderV2,
    ) -> Result<ReassemblyOutput> {
        ensure!(
            bytes.len() <= self.negotiated.limits.max_datagram_size as usize,
            "V2 DATAGRAM exceeds negotiated limit"
        );
        let route_epoch = route_header.session_epoch;
        let state = self
            .epochs
            .get_mut(&route_epoch)
            .context("V2 DATAGRAM belongs to an inactive route epoch")?;
        // `stripe_id == 0` is the overwhelmingly common low-loss path. It can
        // never participate in FEC recovery, so sending it through the stripe
        // decoder only cloned the complete QUIC DATAGRAM, allocated a
        // one-element decode output Vec, and ran stripe expiry bookkeeping.
        // CellV2 still rejects an unstriped parity Cell, preserving the same
        // wire validation without touching any FEC state.
        if route_header.stripe_id == 0 || state.fec_decoder.is_none() {
            let storage = std::mem::take(&mut state.record_storage);
            let mut cell = CellV2::decode_reusing_with_header(bytes, storage, route_header)?;
            let result = state.reassembly.accept_reusing(&mut cell);
            state.record_storage = cell.take_record_storage();
            return result;
        }
        let decoder = state
            .fec_decoder
            .as_mut()
            .expect("V2 FEC decoder presence was checked");
        let decoded = decoder.push(bytes)?;
        let mut combined = ReassemblyOutput {
            records: Vec::new(),
            duplicate_cell: false,
            train_complete: false,
            pressure_evicted_trains: 0,
            reassembly_expired_trains: 0,
            reorder_cells: 0,
            missing_cells: 0,
            fec: FecReceiveStatsV2 {
                parity_received: decoded.parity_received,
                recovered_cells: decoded.recovered_cells,
                wasted_parity: decoded.wasted_parity,
                expired_stripes: decoded.expired_stripes,
                decode_copy_bytes: decoded.decode_copy_bytes,
                recovery_latency_micros: decoded.recovery_latency_micros,
            },
        };
        for cell in decoded.cells {
            let output = state.reassembly.accept(cell)?;
            combined.merge(output);
        }
        Ok(combined)
    }

    pub async fn receive_control(&mut self) -> Result<Bytes> {
        if self.control_stream.is_none() {
            let mut stream = self
                .connection
                .accept_uni()
                .await
                .context("accepting V2 control stream")?;
            let mut magic = [0_u8; 4];
            stream.read_exact(&mut magic).await?;
            ensure!(&magic == CONTROL_MAGIC, "invalid V2 control stream magic");
            self.control_stream = Some(stream);
        }
        let stream = self
            .control_stream
            .as_mut()
            .expect("V2 control stream was accepted");
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(
            length <= self.negotiated.limits.max_control_size as usize,
            "V2 control record exceeds negotiated limit"
        );
        let mut bytes = BytesMut::zeroed(length);
        stream.read_exact(&mut bytes).await?;
        Ok(bytes.freeze())
    }

    pub fn buffered_bytes(&self) -> usize {
        self.epochs
            .values()
            .map(|state| {
                state.reassembly.buffered_bytes()
                    + state
                        .fec_decoder
                        .as_ref()
                        .map_or(0, CellStripeDecoder::buffered_bytes)
            })
            .sum()
    }
}

pub fn completed_record_to_tun(record: super::reassembly::CompletedRecord) -> Result<BytesMut> {
    restore_tun_record_fragments(record.metadata, record.total_len, &record.fragments)
}

fn depth_is_empty(depth: SchedulerDepth) -> bool {
    depth.control_bytes == 0
        && depth.latency_bytes == 0
        && depth.bulk_bytes == 0
        && depth.probe_bytes == 0
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use iroh::{
        Endpoint, EndpointAddr, RelayMode, SecretKey,
        endpoint::{ConnectOptions, TlsSessionPartition, presets},
    };

    use super::*;
    use crate::protocol::v2::routing::{
        NodeIdV2, TopologyLinkV2, TopologyNodeV2, TransitDispositionV2, compile_topology_v2,
    };
    use crate::protocol::v2::session::{
        ConnectionRole, SessionPolicyV2, WireLimitsV2, capability, negotiate_connection_v2,
    };
    use crate::protocol::v2::tuning::RepairWaitPolicyV2;
    use crate::protocol::v2::tuning::{
        Bbr3PresetV2, Bbr3ProposalV2, CoverTrafficProfileV2, TuneDecisionV2, TuneReasonV2,
    };

    #[test]
    fn live_quic_datagram_maximum_remains_authoritative() {
        assert_eq!(
            effective_datagram_maximum(1_414, u16::MAX, usize::from(u16::MAX)),
            1_414
        );
        assert_eq!(
            effective_datagram_maximum(1_414, 1_382, usize::from(u16::MAX)),
            1_382,
            "an older peer's negotiated ceiling remains compatible"
        );
        assert_eq!(
            effective_datagram_maximum(1_414, u16::MAX, 1_200),
            1_200,
            "a compiled transit-path minimum remains authoritative"
        );
    }

    fn repair_key(stripe_id: u32) -> RepairKeyV2 {
        RepairKeyV2 {
            class: TrafficClass::Bulk,
            session_epoch: 7,
            route_label: 9,
            train_id: 11,
            stripe_id,
        }
    }

    fn empty_repair_response(key: RepairKeyV2, request_id: u64) -> RepairResponseV2 {
        RepairResponseV2 {
            key,
            request_id,
            cells: Vec::new(),
        }
    }

    #[test]
    fn pending_repair_matches_id_and_key_and_measures_rtt() {
        let start = Instant::now();
        let key = repair_key(13);
        let mut pending = PendingRepairRequestsV2::new(4, Duration::from_secs(1));
        let request_id = pending.begin(key, 3, start);
        let observation = pending
            .complete(
                &empty_repair_response(key, request_id),
                start + Duration::from_millis(27),
            )
            .unwrap()
            .unwrap();
        assert_eq!(observation.requested_cells, 3);
        assert_eq!(observation.received_cells, 0);
        assert_eq!(observation.latency_micros, 27_000);
        assert!(
            pending
                .complete(
                    &empty_repair_response(key, request_id),
                    start + Duration::from_millis(28)
                )
                .unwrap()
                .is_none(),
            "a duplicate response must not be accepted twice"
        );
    }

    #[test]
    fn pending_repair_rejects_key_substitution_without_consuming_request() {
        let start = Instant::now();
        let key = repair_key(13);
        let mut pending = PendingRepairRequestsV2::new(4, Duration::from_secs(1));
        let request_id = pending.begin(key, 1, start);
        let mismatch = empty_repair_response(repair_key(14), request_id);
        assert!(pending.complete(&mismatch, start).is_err());
        assert!(
            pending
                .complete(
                    &empty_repair_response(key, request_id),
                    start + Duration::from_millis(1)
                )
                .unwrap()
                .is_some(),
            "a forged key must not consume the legitimate request"
        );
    }

    #[test]
    fn pending_repair_expires_and_hard_bounds_outstanding_requests() {
        let start = Instant::now();
        let mut pending = PendingRepairRequestsV2::new(2, Duration::from_millis(10));
        let first = pending.begin(repair_key(1), 1, start);
        let second = pending.begin(repair_key(2), 1, start);
        let third = pending.begin(repair_key(3), 1, start);
        assert_eq!(pending.entries.len(), 2);
        assert!(
            pending
                .complete(&empty_repair_response(repair_key(1), first), start)
                .unwrap()
                .is_none(),
            "capacity pressure must retire the oldest request"
        );
        assert!(
            pending
                .complete(
                    &empty_repair_response(repair_key(2), second),
                    start + Duration::from_millis(10)
                )
                .unwrap()
                .is_none(),
            "a response at the TTL boundary is stale"
        );
        assert!(
            pending
                .complete(
                    &empty_repair_response(repair_key(3), third),
                    start + Duration::from_millis(10)
                )
                .unwrap()
                .is_none()
        );
        assert!(pending.entries.is_empty());
    }

    fn policy(local: &Endpoint, remote: &Endpoint) -> SessionPolicyV2 {
        SessionPolicyV2 {
            network_id: "v2-dataplane-test".into(),
            local_id: local.id(),
            remote_id: remote.id(),
            role: ConnectionRole::Data,
            expected_remote_role: Some(ConnectionRole::Data),
            capabilities: capability::REQUIRED | capability::FEC_STRIPES,
            limits: WireLimitsV2 {
                max_datagram_size: 1382,
                max_control_size: 64 * 1024,
                max_train_size: 32 * 1024,
                max_record_size: u16::MAX as u32,
                max_cells_per_train: 64,
                max_active_trains: 128,
            },
            cover_profile_id: 1,
        }
    }

    async fn connected() -> (Endpoint, Endpoint, Connection, Connection) {
        let alpn = b"h3".to_vec();
        let client = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let target =
            EndpointAddr::new(server.id()).with_ip_addr(*server.addr().ip_addrs().next().unwrap());
        let (client_connection, server_connection) = tokio::join!(
            async {
                client
                    .connect_with_opts(
                        target,
                        &alpn,
                        ConnectOptions::new()
                            .with_visible_server_name("live.example")
                            .with_tls_session_partition(TlsSessionPartition::new(
                                "v2-dataplane-test",
                                1,
                                1,
                            )),
                    )
                    .await
                    .unwrap()
                    .await
            },
            async { server.accept().await.unwrap().accept().unwrap().await }
        );
        (
            client,
            server,
            client_connection.unwrap(),
            server_connection.unwrap(),
        )
    }

    async fn endpoint() -> Endpoint {
        Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .alpns(vec![b"h3".to_vec()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    async fn connect_pair(dialer: &Endpoint, listener: &Endpoint) -> (Connection, Connection) {
        let target = EndpointAddr::new(listener.id())
            .with_ip_addr(*listener.addr().ip_addrs().next().unwrap());
        let (dialed, accepted) = tokio::join!(
            async {
                dialer
                    .connect_with_opts(
                        target,
                        b"h3",
                        ConnectOptions::new()
                            .with_visible_server_name("live.example")
                            .with_tls_session_partition(TlsSessionPartition::new(
                                "v2-dataplane-test",
                                1,
                                1,
                            )),
                    )
                    .await
                    .unwrap()
                    .await
                    .unwrap()
            },
            async {
                listener
                    .accept()
                    .await
                    .unwrap()
                    .accept()
                    .unwrap()
                    .await
                    .unwrap()
            }
        );
        (dialed, accepted)
    }

    #[tokio::test]
    async fn packet_train_crosses_real_quic_in_bounded_quanta() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client, server, client_connection, server_connection) = connected().await;
            let client_policy = policy(&client, &server);
            let server_policy = policy(&server, &client);
            let (client_session, server_session) = tokio::join!(
                negotiate_connection_v2(&client_connection, &client_policy),
                negotiate_connection_v2(&server_connection, &server_policy)
            );
            let mut tx = V2Tx::new_for_adjacency(
                client_connection,
                client_session.unwrap(),
                SchedulerLimits::default(),
                AdjacencyIdV2::new(1).unwrap(),
            )
            .unwrap();
            assert_eq!(
                tx.datagram_send_buffer_limit(),
                INITIAL_SEND_BUFFER_BYTES_V2
            );
            let route_epoch = 99;
            let mut rx = V2Rx::new_for_route_epoch(
                server_connection,
                server_session.unwrap(),
                route_epoch,
                8 * 1024 * 1024,
            )
            .unwrap();
            assert_eq!(
                rx.epochs[&route_epoch]
                    .reassembly
                    .maximum_buffered_bytes(),
                4 * 1024 * 1024,
                "a single live epoch must not reserve memory for absent generations"
            );
            let tuning = TuneDecisionV2 {
                reason: TuneReasonV2::RandomLoss,
                path_epoch: 1,
                sample_count: 10,
                train_target_bytes: 8 * 1024,
                bulk_quantum_cells: 2,
                fec: Some(FecGeometryV2 {
                    data_cells: 4,
                    parity_cells: 1,
                }),
                repair_cache_bytes: 1024 * 1024,
                send_buffer_bytes: 1024 * 1024,
                receive_buffer_bytes: 2 * 1024 * 1024,
                receive_batch: 16,
                cover_profile: CoverTrafficProfileV2::LiveBroadcast,
                cover_overhead_per_mille: 0,
                cover_padding_bytes_per_second: 0,
                repair_retention_millis: 0,
                repair_wait_policy: RepairWaitPolicyV2::HostDefault,
                reassembly_budget_bytes: 0,
                active_train_budget: 0,
                bbr: Bbr3ProposalV2 {
                    preset: Bbr3PresetV2::SharedConservative,
                    up_gain_milli: 1_150,
                    headroom_milli: 250,
                    cwnd_gain_milli: 2_000,
                    pacing_cap_bytes_per_second: 0,
                    loss_is_congestion: false,
                },
            };
            tx.apply_tuning(tuning).unwrap();
            assert_eq!(tx.datagram_send_buffer_limit(), tuning.send_buffer_bytes);
            rx.apply_tuning(tuning, Duration::from_secs(1)).unwrap();
            assert_eq!(rx.maximum_buffered_bytes(), tuning.receive_buffer_bytes);
            assert_eq!(
                rx.epochs[&route_epoch]
                    .reassembly
                    .maximum_buffered_bytes(),
                1024 * 1024
            );
            // An explicit reassembly budget shrinks the per-epoch reassembly
            // share below the even split, and the active-train budget caps
            // the negotiated wire limit.
            let budgeted = TuneDecisionV2 {
                receive_buffer_bytes: 8 * 1024 * 1024,
                reassembly_budget_bytes: 2 * 1024 * 1024,
                active_train_budget: 8,
                ..tuning
            };
            rx.apply_tuning(budgeted, Duration::from_secs(1)).unwrap();
            assert_eq!(rx.maximum_buffered_bytes(), 8 * 1024 * 1024);
            assert_eq!(
                rx.epochs[&route_epoch]
                    .reassembly
                    .maximum_buffered_bytes(),
                2 * 1024 * 1024,
                "reassembly share follows the explicit budget, not the even split"
            );
            assert_eq!(
                rx.epochs[&route_epoch].reassembly.maximum_active_trains(),
                8.min(rx.negotiated.limits.max_active_trains as usize)
            );
            // Back to zero: the even split and the negotiated limit return.
            rx.apply_tuning(tuning, Duration::from_secs(1)).unwrap();
            assert_eq!(
                rx.epochs[&route_epoch]
                    .reassembly
                    .maximum_buffered_bytes(),
                1024 * 1024
            );
            assert_eq!(
                rx.epochs[&route_epoch].reassembly.maximum_active_trains(),
                rx.negotiated.limits.max_active_trains as usize
            );
            // QUIC may expose its optimistic ceiling briefly before initial
            // path validation installs the real UDP payload maximum. Wait
            // for a stable value so this round-trip test exercises Cell/FEC
            // behavior rather than the separately tested PMTU-race drop path.
            let mut previous_maximum = None;
            let mut stable_samples = 0;
            while stable_samples < 10 {
                let maximum = tx.connection.max_datagram_size().unwrap();
                stable_samples = if previous_maximum == Some(maximum) {
                    stable_samples + 1
                } else {
                    0
                };
                previous_maximum = Some(maximum);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let expected = (1..=20)
                .map(|record_id| (record_id, Bytes::from(vec![record_id as u8; 1500])))
                .collect::<HashMap<_, _>>();
            tx.enqueue_control(Bytes::from_static(b"route-generation-1"))
                .unwrap();
            let train_ids = tx
                .enqueue_routed_records_auto(
                    42,
                    TrafficClass::Bulk,
                    ResolvedRouteV2 {
                        adjacency: crate::protocol::v2::routing::AdjacencyIdV2::new(1).unwrap(),
                        route_label: crate::protocol::v2::routing::RouteLabelV2::new(9).unwrap(),
                        route_epoch,
                        maximum_datagram_size: 1_382,
                    },
                    64,
                    expected.iter().map(|(&record_id, data)| TrainRecord {
                        record_id,
                        metadata: Bytes::new(),
                        data: data.clone(),
                    }),
                )
                .unwrap();
            assert!(train_ids.len() > 1);
            assert!(
                tx.enqueue_cover_padding(CoverTrafficProfileV2::LiveBroadcast)
                    .unwrap()
            );

            let mut sent_datagrams = 0;
            let mut cover_padding_bytes = 0;
            let mut dropped_datagrams = 0;
            let mut data_cell_datagrams = 0;
            let mut data_cell_payload_bytes = 0;
            let mut fec_datagrams = 0;
            let mut train_stat_reports = 0;
            let mut fec_stripes_built = 0;
            let mut fec_protected_data_cells = 0;
            while tx.has_pending() {
                if let Some(progress) = tx.send_next().await.unwrap() {
                    sent_datagrams += progress.datagrams;
                    cover_padding_bytes += progress.cover_padding_bytes;
                    dropped_datagrams += progress.dropped_datagrams;
                    data_cell_datagrams += progress.data_cell_datagrams;
                    data_cell_payload_bytes += progress.data_cell_payload_bytes;
                    fec_datagrams += progress.fec_datagrams;
                    if let Some(stats) = progress.train_stats {
                        train_stat_reports += 1;
                        fec_stripes_built += stats.fec_stripes;
                        fec_protected_data_cells += stats.fec_protected_data_cells;
                    }
                }
            }
            assert!(tx.stats().bulk_quantum_count > 1);
            assert!(
                sent_datagrams > 20,
                "sent={sent_datagrams} data={data_cell_datagrams} fec={fec_datagrams} dropped={dropped_datagrams}"
            );
            assert!(
                data_cell_datagrams > 20,
                "sent={sent_datagrams} data={data_cell_datagrams} fec={fec_datagrams} dropped={dropped_datagrams}"
            );
            assert!(data_cell_payload_bytes >= 20 * 1_500);
            assert!(fec_datagrams > 0);
            assert!(fec_stripes_built > 0);
            assert!(fec_protected_data_cells > 0);
            assert_eq!(train_stat_reports, train_ids.len());
            assert!(cover_padding_bytes > 0 || dropped_datagrams > 0);
            assert_eq!(
                rx.receive_control().await.unwrap(),
                Bytes::from_static(b"route-generation-1")
            );

            let mut received = HashMap::new();
            let mut received_datagrams = 0;
            while received_datagrams < sent_datagrams {
                for record in rx.receive_cell().await.unwrap().records {
                    received.insert(record.record_id, record.coalesce());
                }
                received_datagrams += 1;
            }
            assert_eq!(received, expected);
            assert_eq!(rx.buffered_bytes(), 0);

            // A route generation can change independently of the QUIC
            // session. Install the receiver generation before the writer
            // publishes work for it and prove both generations coexist.
            rx.activate_route_epoch(100).unwrap();
            assert!(rx.epochs.values().all(|state| {
                state.reassembly.maximum_buffered_bytes() == 512 * 1024
            }));
            tx.enqueue_routed_records_auto(
                43,
                TrafficClass::Bulk,
                ResolvedRouteV2 {
                    adjacency: AdjacencyIdV2::new(1).unwrap(),
                    route_label: crate::protocol::v2::routing::RouteLabelV2::new(10).unwrap(),
                    route_epoch: 100,
                    maximum_datagram_size: 1_382,
                },
                64,
                [TrainRecord {
                    record_id: 1,
                    metadata: Bytes::new(),
                    data: Bytes::from_static(b"next-route-generation"),
                }],
            )
            .unwrap();
            while tx.has_pending() {
                tx.send_next().await.unwrap();
            }
            let mut records = Vec::new();
            while records.is_empty() {
                records.extend(rx.receive_cell().await.unwrap().records);
            }
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].coalesce(),
                Bytes::from_static(b"next-route-generation")
            );

            // The window is strictly bounded and retires the oldest route
            // generation only after two successors have also been installed.
            rx.activate_route_epoch(101).unwrap();
            assert!(rx.epochs.values().all(|state| {
                state.reassembly.maximum_buffered_bytes()
                    == tuning.receive_buffer_bytes / (MAX_ACTIVE_ROUTE_EPOCHS * 2)
            }));
            rx.activate_route_epoch(102).unwrap();
            assert_eq!(
                rx.active_route_epochs().collect::<Vec<_>>(),
                vec![100, 101, 102]
            );
            rx.activate_route_epoch(101).unwrap();
            assert_eq!(
                rx.active_route_epochs().collect::<Vec<_>>(),
                vec![100, 101, 102]
            );
            client.close().await;
            server.close().await;
        })
        .await
        .expect("V2 QUIC dataplane test timed out");
    }

    #[tokio::test]
    async fn packet_train_transits_two_real_quic_adjacencies_without_reassembly() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let a = endpoint().await;
            let b = endpoint().await;
            let c = endpoint().await;
            let (a_to_b, b_from_a) = connect_pair(&a, &b).await;
            let (b_to_c, c_from_b) = connect_pair(&b, &c).await;

            // Session negotiation remains adjacency-local (1,382 bytes),
            // while the topology advertises a narrower 1,100-byte B-C path.
            // The source must compile the path minimum instead of depending
            // on an artificially conservative first-hop session limit. Keep
            // the fixture below QUIC's IPv6-minimum live DATAGRAM payload so
            // an asynchronous PMTU confirmation cannot make the test flaky.
            let a_policy = policy(&a, &b);
            let b_ab_policy = policy(&b, &a);
            let b_bc_policy = policy(&b, &c);
            let c_policy = policy(&c, &b);
            let (a_session, b_ab_session, b_bc_session, c_session) = tokio::join!(
                negotiate_connection_v2(&a_to_b, &a_policy),
                negotiate_connection_v2(&b_from_a, &b_ab_policy),
                negotiate_connection_v2(&b_to_c, &b_bc_policy),
                negotiate_connection_v2(&c_from_b, &c_policy),
            );
            let a_session = a_session.unwrap();
            let b_ab_session = b_ab_session.unwrap();
            let b_bc_session = b_bc_session.unwrap();
            let c_session = c_session.unwrap();

            let adjacency_datagram_maximum =
                |left: &iroh::endpoint::Connection,
                 left_session: &NegotiatedSessionV2,
                 right: &iroh::endpoint::Connection,
                 right_session: &NegotiatedSessionV2| {
                    left.max_datagram_size()
                        .unwrap()
                        .min(right.max_datagram_size().unwrap())
                        .min(left_session.limits.max_datagram_size.into())
                        .min(right_session.limits.max_datagram_size.into())
                        as u16
                };
            let ab_maximum =
                adjacency_datagram_maximum(&a_to_b, &a_session, &b_from_a, &b_ab_session);
            let bc_maximum =
                adjacency_datagram_maximum(&b_to_c, &b_bc_session, &c_from_b, &c_session);
            let bc_advertised_maximum = bc_maximum.min(1_100);
            let adjacency = |value| AdjacencyIdV2::new(value).unwrap();
            let topology = compile_topology_v2(
                1,
                55,
                vec![
                    TopologyNodeV2 {
                        node_id: NodeIdV2(*a.id().as_bytes()),
                        advertised_prefixes: Vec::new(),
                        transit_enabled: false,
                        underlay_exclusion_prefixes: Vec::new(),
                    },
                    TopologyNodeV2 {
                        node_id: NodeIdV2(*b.id().as_bytes()),
                        advertised_prefixes: Vec::new(),
                        transit_enabled: true,
                        underlay_exclusion_prefixes: Vec::new(),
                    },
                    TopologyNodeV2 {
                        node_id: NodeIdV2(*c.id().as_bytes()),
                        advertised_prefixes: vec!["11.6.1.0/24".parse().unwrap()],
                        transit_enabled: false,
                        underlay_exclusion_prefixes: Vec::new(),
                    },
                ],
                vec![
                    TopologyLinkV2 {
                        left: NodeIdV2(*a.id().as_bytes()),
                        right: NodeIdV2(*b.id().as_bytes()),
                        left_adjacency: adjacency(12),
                        right_adjacency: adjacency(21),
                        cost: 1,
                        healthy: true,
                        maximum_datagram_size: ab_maximum,
                    },
                    TopologyLinkV2 {
                        left: NodeIdV2(*b.id().as_bytes()),
                        right: NodeIdV2(*c.id().as_bytes()),
                        left_adjacency: adjacency(23),
                        right_adjacency: adjacency(32),
                        cost: 1,
                        healthy: true,
                        maximum_datagram_size: bc_advertised_maximum,
                    },
                ],
                false,
            )
            .unwrap();
            let a_snapshot = topology.snapshot(NodeIdV2(*a.id().as_bytes())).unwrap();
            let b_snapshot = topology.snapshot(NodeIdV2(*b.id().as_bytes())).unwrap();
            let c_snapshot = topology.snapshot(NodeIdV2(*c.id().as_bytes())).unwrap();
            let route = a_snapshot
                .lookup_destination("11.6.1.48".parse().unwrap())
                .unwrap();
            assert_eq!(route.adjacency, adjacency(12));
            assert_eq!(
                route.maximum_datagram_size,
                ab_maximum.min(bc_advertised_maximum)
            );

            let mut a_tx = V2Tx::new_for_adjacency(
                a_to_b,
                a_session,
                SchedulerLimits::default(),
                adjacency(12),
            )
            .unwrap();
            let b_tx_limit = b_bc_session.limits.max_datagram_size;
            let mut b_tx = V2Tx::new_for_adjacency(
                b_to_c,
                b_bc_session,
                SchedulerLimits::default(),
                adjacency(23),
            )
            .unwrap();
            let mut c_rx = V2Rx::new_for_route_epoch(
                c_from_b,
                c_session,
                topology.route_epoch,
                8 * 1024 * 1024,
            )
            .unwrap();

            let payload = Bytes::from(vec![0x5a; 16 * 1024]);
            a_tx.enqueue_routed_records_auto(
                7,
                TrafficClass::Bulk,
                route,
                8,
                [TrainRecord {
                    record_id: 1,
                    metadata: Bytes::new(),
                    data: payload.clone(),
                }],
            )
            .unwrap();
            let mut sent = 0;
            while a_tx.has_pending() {
                sent += a_tx.send_next().await.unwrap().unwrap().datagrams;
            }
            assert!(sent > 1);

            let mut forwarded_sample = None::<Bytes>;
            for _ in 0..sent {
                let incoming = b_from_a.read_datagram().await.unwrap();
                let TransitDispositionV2::Forward { next_hop, cell } =
                    b_snapshot.dispatch_cell(adjacency(21), incoming).unwrap()
                else {
                    panic!("B must forward A's route label");
                };
                assert_eq!(next_hop, adjacency(23));
                forwarded_sample.get_or_insert_with(|| cell.bytes.clone());
                assert!(b_tx.enqueue_forwarded_cell(7, cell.bytes).unwrap());
            }
            let mut forwarded = 0;
            while b_tx.has_pending() {
                forwarded += b_tx.send_next().await.unwrap().unwrap().datagrams;
            }

            let mut oversized = forwarded_sample.unwrap().to_vec();
            let oversized_length = usize::from(b_tx_limit) + 1;
            oversized.resize(oversized_length, 0);
            let oversized_payload = u16::try_from(oversized.len() - super::super::cell::HEADER_LEN)
                .unwrap()
                .to_be_bytes();
            oversized[32..34].copy_from_slice(&oversized_payload);
            assert!(matches!(
                b_tx.admit_forwarded_cells(8, vec![Bytes::from(oversized)])
                    .unwrap(),
                ForwardAdmissionV2::PathMtuExceeded {
                    observed_datagram_size,
                    maximum_datagram_size,
                    ..
                } if observed_datagram_size == oversized_length
                    && maximum_datagram_size <= usize::from(b_tx_limit)
            ));
            assert_eq!(forwarded, sent);

            let mut records = Vec::new();
            for _ in 0..forwarded {
                let incoming = c_rx.receive_datagram().await.unwrap();
                let TransitDispositionV2::Local { cell, header } =
                    c_snapshot.dispatch_cell(adjacency(32), incoming).unwrap()
                else {
                    panic!("C must locally deliver A's route label");
                };
                assert_eq!(header.overlay_hops, 1);
                records.extend(c_rx.accept_routed_datagram(cell, header).unwrap().records);
            }
            assert_eq!(records.len(), 1);
            assert_eq!(records.remove(0).coalesce(), payload);

            a_tx.enqueue_routed_records_auto(
                8,
                TrafficClass::Latency,
                route,
                1,
                [TrainRecord {
                    record_id: 1,
                    metadata: Bytes::new(),
                    data: Bytes::from_static(b"ttl"),
                }],
            )
            .unwrap();
            a_tx.send_next().await.unwrap();
            let incoming = b_from_a.read_datagram().await.unwrap();
            let TransitDispositionV2::TtlExpired(oam) =
                b_snapshot.dispatch_cell(adjacency(21), incoming).unwrap()
            else {
                panic!("B must emit TTL-expired OAM");
            };
            assert_eq!(oam.reporter, *b.id().as_bytes());
            assert_eq!(oam.incoming, adjacency(21));

            a.close().await;
            b.close().await;
            c.close().await;
        })
        .await
        .expect("three-node V2 transit test timed out");
    }
}
