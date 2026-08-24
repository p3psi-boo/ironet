use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use bytes::Bytes;
use iroh::endpoint::DatagramPayload;

use crate::buffer::RecyclingBytePool;
use rustc_hash::FxHashMap as HashMap;

use super::{
    cell::{CellRouteHeaderV2, CellV2, TrafficClass},
    train::{PacketTrain, SegmentBufferPool, TrainBuildStats},
};

pub const MAX_QUANTUM_BYTES: usize = 16 * 1024;
pub const MAX_QUANTUM_CELLS: usize = 8;
const DEFAULT_LATENCY_DEADLINE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy)]
pub struct SchedulerLimits {
    pub control_bytes: usize,
    pub latency_bytes: usize,
    pub bulk_bytes: usize,
    pub probe_bytes: usize,
    pub application_bytes: usize,
    pub bulk_reserve_bytes: usize,
    pub bulk_drr_quantum_bytes: usize,
    pub latency_burst_bytes: usize,
    pub maximum_quantum_cells: usize,
    pub maximum_quantum_bytes: usize,
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self {
            control_bytes: 1024 * 1024,
            latency_bytes: 2 * 1024 * 1024,
            bulk_bytes: 8 * 1024 * 1024,
            probe_bytes: 256 * 1024,
            application_bytes: 8 * 1024 * 1024,
            bulk_reserve_bytes: 1024 * 1024,
            bulk_drr_quantum_bytes: 8 * 1400,
            latency_burst_bytes: 64 * 1024,
            maximum_quantum_cells: MAX_QUANTUM_CELLS,
            maximum_quantum_bytes: MAX_QUANTUM_BYTES,
        }
    }
}

impl SchedulerLimits {
    fn validate(self) -> Result<()> {
        ensure!(self.control_bytes > 0, "V2 control queue limit is zero");
        ensure!(self.latency_bytes > 0, "V2 latency queue limit is zero");
        ensure!(self.bulk_bytes > 0, "V2 bulk queue limit is zero");
        ensure!(self.probe_bytes > 0, "V2 probe queue limit is zero");
        ensure!(
            self.application_bytes >= self.bulk_reserve_bytes,
            "V2 bulk reserve exceeds application budget"
        );
        ensure!(self.bulk_drr_quantum_bytes > 0, "V2 DRR quantum is zero");
        ensure!(
            (1..=MAX_QUANTUM_CELLS).contains(&self.maximum_quantum_cells),
            "V2 cell quantum exceeds hard limit"
        );
        ensure!(
            (1..=MAX_QUANTUM_BYTES).contains(&self.maximum_quantum_bytes),
            "V2 byte quantum exceeds hard limit"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchedulerDepth {
    pub control_bytes: usize,
    pub latency_bytes: usize,
    pub bulk_bytes: usize,
    pub probe_bytes: usize,
    pub latency_trains: usize,
    pub bulk_trains: usize,
    pub bulk_flows: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchedulerStats {
    pub quantum_count: u64,
    pub quantum_bytes: u64,
    pub bulk_quantum_count: u64,
    pub latency_quantum_count: u64,
    pub bulk_preemptions: u64,
    pub bulk_forced_service: u64,
    pub bulk_evicted_bytes: u64,
    pub rejected_bytes: u64,
    pub maximum_sojourn_micros: u64,
    pub latency_deadline_misses: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledCellV2 {
    pub payload: DatagramPayload,
    pub header: CellRouteHeaderV2,
}

impl ScheduledCellV2 {
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellQuantum {
    pub class: TrafficClass,
    /// Local-only strict latency tier; never encoded on the wire.
    pub priority: bool,
    pub flow_id: u64,
    pub train_id: u64,
    pub cells: Vec<ScheduledCellV2>,
    pub train_finished: bool,
    pub sojourn: Duration,
    /// A latency quantum selected while Bulk was immediately serviceable.
    pub bulk_preemption: bool,
    /// Build accounting is attached exactly once, to the first quantum of a
    /// locally originated PacketTrain. Transit Cells intentionally carry no
    /// local build stats.
    pub train_stats: Option<TrainBuildStats>,
}

impl CellQuantum {
    pub fn bytes(&self) -> usize {
        self.cells.iter().map(ScheduledCellV2::len).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledWork {
    Control(Bytes),
    Cells(CellQuantum),
    Probe(Bytes),
}

#[derive(Debug)]
struct TrainCursor {
    class: TrafficClass,
    flow_id: u64,
    train_id: u64,
    cells: VecDeque<ScheduledCellV2>,
    bytes: usize,
    enqueued: Instant,
    deadline: Option<Instant>,
    /// Local-only strict latency tier. This is never serialized into a Cell:
    /// it exists so semantic control packets cannot sit behind expired
    /// best-effort latency work in the same EDF queue.
    priority: bool,
    stats: Option<TrainBuildStats>,
}

impl TrainCursor {
    fn new(
        flow_id: u64,
        train: PacketTrain,
        maximum_datagram_size: usize,
        deadline: Option<Instant>,
        cell_pool: &mut RecyclingBytePool,
        mut segment_pool: Option<&mut SegmentBufferPool>,
    ) -> Result<Self> {
        ensure!(!train.cells.is_empty(), "cannot schedule an empty V2 train");
        let class = train.cells[0].class;
        let train_id = train.cells[0].train_id;
        let mut cells = VecDeque::with_capacity(train.cells.len());
        let mut bytes = 0_usize;
        for cell in train.cells {
            ensure!(cell.class == class, "V2 train mixes traffic classes");
            ensure!(cell.train_id == train_id, "V2 train mixes train IDs");
            let mut tail = None;
            let mut header = None;
            let head = cell_pool.build(|out| {
                let (encoded_tail, encoded_header) =
                    cell.encode_datagram_parts_into(maximum_datagram_size, out)?;
                tail = encoded_tail;
                header = Some(encoded_header);
                Ok::<_, anyhow::Error>(())
            })?;
            let payload = match tail {
                Some(tail) => DatagramPayload::split(head, tail),
                None => DatagramPayload::contiguous(head),
            };
            if let Some(segment_pool) = segment_pool.as_deref_mut()
                && let super::cell::CellBody::Records(segments) = cell.body
            {
                segment_pool.recycle(segments);
            }
            bytes = bytes
                .checked_add(payload.len())
                .ok_or_else(|| anyhow::anyhow!("V2 scheduled train byte overflow"))?;
            cells.push_back(ScheduledCellV2 {
                payload,
                header: header.expect("V2 Cell encoder returned its fixed header"),
            });
        }
        Ok(Self {
            class,
            flow_id,
            train_id,
            cells,
            bytes,
            enqueued: Instant::now(),
            deadline,
            priority: false,
            stats: Some(train.stats),
        })
    }

    fn from_encoded(
        flow_id: u64,
        class: TrafficClass,
        train_id: u64,
        cells: Vec<Bytes>,
        stats: Option<TrainBuildStats>,
    ) -> Result<Self> {
        ensure!(
            !cells.is_empty(),
            "cannot schedule an empty encoded V2 train"
        );
        let mut bytes = 0_usize;
        let mut scheduled = VecDeque::with_capacity(cells.len());
        for encoded in cells {
            let cell = CellV2::decode(encoded.clone())?;
            ensure!(
                cell.class == class,
                "encoded V2 train mixes traffic classes"
            );
            ensure!(
                cell.train_id == train_id,
                "encoded V2 train mixes train IDs"
            );
            bytes = bytes
                .checked_add(encoded.len())
                .ok_or_else(|| anyhow::anyhow!("encoded V2 train byte overflow"))?;
            scheduled.push_back(ScheduledCellV2 {
                header: CellRouteHeaderV2::decode(&encoded)?,
                payload: DatagramPayload::contiguous(encoded),
            });
        }
        Ok(Self {
            class,
            flow_id,
            train_id,
            cells: scheduled,
            bytes,
            enqueued: Instant::now(),
            deadline: None,
            priority: false,
            stats,
        })
    }

    /// Build a transit cursor from the fixed routing shim only. Transit must
    /// not parse Record segments or enter FEC/reassembly state merely to use
    /// the same bounded class scheduler as locally originated Cells.
    fn from_forwarded(flow_id: u64, cells: Vec<Bytes>) -> Result<Self> {
        ensure!(!cells.is_empty(), "cannot schedule an empty transit batch");
        let first = CellRouteHeaderV2::decode(&cells[0])?;
        let mut bytes = 0_usize;
        let mut scheduled = VecDeque::with_capacity(cells.len());
        for cell in cells {
            let header = CellRouteHeaderV2::decode(&cell)?;
            ensure!(
                header.class == first.class && header.train_id == first.train_id,
                "V2 transit batch mixes class or PacketTrain"
            );
            bytes = bytes
                .checked_add(cell.len())
                .ok_or_else(|| anyhow::anyhow!("V2 transit batch byte overflow"))?;
            scheduled.push_back(ScheduledCellV2 {
                payload: DatagramPayload::contiguous(cell),
                header,
            });
        }
        Ok(Self {
            class: first.class,
            flow_id,
            train_id: first.train_id,
            cells: scheduled,
            bytes,
            enqueued: Instant::now(),
            deadline: None,
            priority: false,
            stats: None,
        })
    }

    fn pop_cells(&mut self, maximum_cells: usize, maximum_bytes: usize) -> Vec<ScheduledCellV2> {
        let mut output = Vec::with_capacity(maximum_cells);
        let mut bytes = 0_usize;
        while output.len() < maximum_cells {
            let Some(next) = self.cells.front() else {
                break;
            };
            if !output.is_empty() && bytes.saturating_add(next.len()) > maximum_bytes {
                break;
            }
            // A negotiated Cell may itself be larger than a lowered runtime
            // quantum. It still has to make progress, but never above the V2
            // hard ceiling enforced at scheduler construction.
            if output.is_empty() && next.len() > maximum_bytes {
                break;
            }
            let cell = self.cells.pop_front().expect("checked non-empty");
            bytes += cell.len();
            self.bytes -= cell.len();
            output.push(cell);
        }
        output
    }
}

#[derive(Debug, Default)]
struct BulkFlow {
    deficit: usize,
    trains: VecDeque<TrainCursor>,
}

#[derive(Debug)]
pub struct V2Scheduler {
    limits: SchedulerLimits,
    cell_pool: RecyclingBytePool,
    control: VecDeque<Bytes>,
    latency: VecDeque<TrainCursor>,
    bulk: HashMap<u64, BulkFlow>,
    active_bulk: VecDeque<u64>,
    probes: VecDeque<Bytes>,
    depth: SchedulerDepth,
    stats: SchedulerStats,
    latency_bytes_since_bulk: usize,
    bulk_was_preemptible: bool,
}

impl V2Scheduler {
    pub fn new(limits: SchedulerLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            // Keep ownership descriptors ready but allocate wire storage at
            // the negotiated Cell size on first use. Preallocating every peer
            // at the 8 KiB hard ceiling would waste 2 MiB per idle adjacency.
            cell_pool: RecyclingBytePool::new(256, 0),
            limits,
            control: VecDeque::new(),
            latency: VecDeque::new(),
            bulk: HashMap::default(),
            active_bulk: VecDeque::new(),
            probes: VecDeque::new(),
            depth: SchedulerDepth::default(),
            stats: SchedulerStats::default(),
            latency_bytes_since_bulk: 0,
            bulk_was_preemptible: false,
        })
    }

    pub fn enqueue_control(&mut self, bytes: Bytes) -> bool {
        self.enqueue_bytes(bytes, TrafficQueue::Control)
    }

    pub fn enqueue_probe(&mut self, bytes: Bytes) -> bool {
        self.enqueue_bytes(bytes, TrafficQueue::Probe)
    }

    pub fn enqueue_train(
        &mut self,
        flow_id: u64,
        train: PacketTrain,
        maximum_datagram_size: usize,
    ) -> Result<bool> {
        self.enqueue_train_with_deadline(flow_id, train, maximum_datagram_size, None)
    }

    pub fn enqueue_train_with_deadline(
        &mut self,
        flow_id: u64,
        train: PacketTrain,
        maximum_datagram_size: usize,
        deadline: Option<Instant>,
    ) -> Result<bool> {
        self.enqueue_train_with_scheduling(flow_id, train, maximum_datagram_size, deadline, false)
    }

    pub fn enqueue_train_with_scheduling(
        &mut self,
        flow_id: u64,
        train: PacketTrain,
        maximum_datagram_size: usize,
        deadline: Option<Instant>,
        priority: bool,
    ) -> Result<bool> {
        ensure!(flow_id != 0, "V2 flow ID zero is reserved");
        let mut cursor = TrainCursor::new(
            flow_id,
            train,
            maximum_datagram_size,
            deadline,
            &mut self.cell_pool,
            None,
        )?;
        cursor.priority = priority;
        self.enqueue_cursor(cursor)
    }

    pub(crate) fn enqueue_train_with_scheduling_pooled(
        &mut self,
        flow_id: u64,
        train: PacketTrain,
        maximum_datagram_size: usize,
        deadline: Option<Instant>,
        priority: bool,
        segment_pool: &mut SegmentBufferPool,
    ) -> Result<bool> {
        ensure!(flow_id != 0, "V2 flow ID zero is reserved");
        let mut cursor = TrainCursor::new(
            flow_id,
            train,
            maximum_datagram_size,
            deadline,
            &mut self.cell_pool,
            Some(segment_pool),
        )?;
        cursor.priority = priority;
        self.enqueue_cursor(cursor)
    }

    pub fn enqueue_encoded_train(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        train_id: u64,
        cells: Vec<Bytes>,
        stats: Option<TrainBuildStats>,
    ) -> Result<bool> {
        self.enqueue_encoded_train_with_deadline(flow_id, class, train_id, cells, stats, None)
    }

    pub fn enqueue_encoded_train_with_deadline(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        train_id: u64,
        cells: Vec<Bytes>,
        stats: Option<TrainBuildStats>,
        deadline: Option<Instant>,
    ) -> Result<bool> {
        self.enqueue_encoded_train_with_scheduling(
            flow_id, class, train_id, cells, stats, deadline, false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_encoded_train_with_scheduling(
        &mut self,
        flow_id: u64,
        class: TrafficClass,
        train_id: u64,
        cells: Vec<Bytes>,
        stats: Option<TrainBuildStats>,
        deadline: Option<Instant>,
        priority: bool,
    ) -> Result<bool> {
        ensure!(flow_id != 0, "V2 flow ID zero is reserved");
        let mut cursor = TrainCursor::from_encoded(flow_id, class, train_id, cells, stats)?;
        cursor.deadline = deadline;
        cursor.priority = priority;
        self.enqueue_cursor(cursor)
    }

    pub fn enqueue_forwarded_cells(&mut self, flow_id: u64, cells: Vec<Bytes>) -> Result<bool> {
        ensure!(flow_id != 0, "V2 flow ID zero is reserved");
        let cursor = TrainCursor::from_forwarded(flow_id, cells)?;
        self.enqueue_cursor(cursor)
    }

    fn enqueue_cursor(&mut self, mut cursor: TrainCursor) -> Result<bool> {
        ensure!(
            cursor
                .cells
                .iter()
                .all(|cell| cell.len() <= self.limits.maximum_quantum_bytes),
            "V2 Cell exceeds the scheduler quantum byte ceiling"
        );
        let bytes = cursor.bytes;
        let flow_id = cursor.flow_id;
        match cursor.class {
            TrafficClass::Latency => {
                cursor.deadline = Some(
                    cursor
                        .deadline
                        .unwrap_or_else(|| cursor.enqueued + DEFAULT_LATENCY_DEADLINE),
                );
                if bytes > self.limits.latency_bytes {
                    self.reject(bytes);
                    return Ok(false);
                }
                while self.depth.latency_bytes.saturating_add(bytes)
                    > self
                        .limits
                        .application_bytes
                        .saturating_sub(self.depth.bulk_bytes)
                {
                    if !self.evict_bulk_elastic() {
                        self.reject(bytes);
                        return Ok(false);
                    }
                }
                if self.depth.latency_bytes.saturating_add(bytes) > self.limits.latency_bytes {
                    self.reject(bytes);
                    return Ok(false);
                }
                self.depth.latency_bytes += bytes;
                self.depth.latency_trains += 1;
                let deadline = cursor.deadline.expect("latency deadline was assigned");
                let priority = cursor.priority;
                let position = self
                    .latency
                    .iter()
                    .position(|queued| {
                        (priority && !queued.priority)
                            || (priority == queued.priority
                                && queued.deadline.is_some_and(|value| value > deadline))
                    })
                    .unwrap_or(self.latency.len());
                self.latency.insert(position, cursor);
            }
            TrafficClass::Bulk => {
                if self.depth.bulk_bytes.saturating_add(bytes) > self.limits.bulk_bytes
                    || self
                        .depth
                        .bulk_bytes
                        .saturating_add(self.depth.latency_bytes)
                        .saturating_add(bytes)
                        > self.limits.application_bytes
                {
                    self.reject(bytes);
                    return Ok(false);
                }
                let flow = self.bulk.entry(flow_id).or_default();
                let was_empty = flow.trains.is_empty();
                flow.trains.push_back(cursor);
                if was_empty {
                    self.active_bulk.push_back(flow_id);
                    self.depth.bulk_flows += 1;
                }
                self.depth.bulk_bytes += bytes;
                self.depth.bulk_trains += 1;
            }
        }
        Ok(true)
    }

    pub fn pop(&mut self) -> Option<ScheduledWork> {
        if let Some(bytes) = self.control.pop_front() {
            self.depth.control_bytes -= bytes.len();
            return Some(ScheduledWork::Control(bytes));
        }

        let force_bulk = !self.active_bulk.is_empty()
            && !self.latency.is_empty()
            && self.latency_bytes_since_bulk >= self.limits.latency_burst_bytes;
        if !force_bulk && let Some(quantum) = self.pop_latency() {
            if self.bulk_was_preemptible {
                self.stats.bulk_preemptions += 1;
                self.bulk_was_preemptible = false;
            }
            return Some(ScheduledWork::Cells(quantum));
        }
        if let Some(quantum) = self.pop_bulk() {
            if force_bulk {
                self.stats.bulk_forced_service += 1;
            }
            self.latency_bytes_since_bulk = 0;
            self.bulk_was_preemptible = !self.active_bulk.is_empty() || self.depth.bulk_bytes > 0;
            return Some(ScheduledWork::Cells(quantum));
        }
        if let Some(quantum) = self.pop_latency() {
            return Some(ScheduledWork::Cells(quantum));
        }
        self.probes.pop_front().map(|bytes| {
            self.depth.probe_bytes -= bytes.len();
            ScheduledWork::Probe(bytes)
        })
    }

    pub fn depth(&self) -> SchedulerDepth {
        self.depth
    }

    /// Whether work exists that must be able to overtake a Bulk quantum whose
    /// asynchronous QUIC admission future was cancelled while waiting for
    /// mailbox capacity.
    pub fn has_strict_urgent(&self) -> bool {
        !self.control.is_empty() || self.latency.front().is_some_and(|cursor| cursor.priority)
    }

    pub fn stats(&self) -> SchedulerStats {
        self.stats
    }

    pub fn set_bulk_quantum_cells(&mut self, cells: usize) -> Result<()> {
        ensure!(
            (1..=MAX_QUANTUM_CELLS).contains(&cells),
            "V2 tuned Bulk quantum exceeds hard Cell limit"
        );
        self.limits.maximum_quantum_cells = cells;
        Ok(())
    }

    fn pop_latency(&mut self) -> Option<CellQuantum> {
        let cursor = self.latency.front_mut()?;
        let cells = cursor.pop_cells(1, self.limits.maximum_quantum_bytes);
        if cells.is_empty() {
            return None;
        }
        let bytes = cells.iter().map(ScheduledCellV2::len).sum::<usize>();
        let quantum = CellQuantum {
            class: TrafficClass::Latency,
            priority: cursor.priority,
            flow_id: cursor.flow_id,
            train_id: cursor.train_id,
            cells,
            train_finished: cursor.cells.is_empty(),
            sojourn: cursor.enqueued.elapsed(),
            bulk_preemption: self.bulk_was_preemptible,
            train_stats: cursor.stats.take(),
        };
        if cursor
            .deadline
            .is_some_and(|deadline| Instant::now() > deadline)
        {
            self.stats.latency_deadline_misses += 1;
        }
        self.depth.latency_bytes -= bytes;
        self.latency_bytes_since_bulk = self.latency_bytes_since_bulk.saturating_add(bytes);
        if quantum.train_finished {
            self.latency.pop_front();
            self.depth.latency_trains -= 1;
        }
        self.record_quantum(&quantum);
        self.stats.latency_quantum_count += 1;
        Some(quantum)
    }

    fn pop_bulk(&mut self) -> Option<CellQuantum> {
        let visits = self.active_bulk.len();
        for _ in 0..visits {
            let flow_id = self.active_bulk.pop_front()?;
            let Some(flow) = self.bulk.get_mut(&flow_id) else {
                continue;
            };
            flow.deficit = flow
                .deficit
                .saturating_add(self.limits.bulk_drr_quantum_bytes)
                .min(self.limits.maximum_quantum_bytes * 2);
            let Some(cursor) = flow.trains.front_mut() else {
                self.bulk.remove(&flow_id);
                self.depth.bulk_flows -= 1;
                continue;
            };
            let budget = flow.deficit.min(self.limits.maximum_quantum_bytes);
            let cells = cursor.pop_cells(self.limits.maximum_quantum_cells, budget);
            if cells.is_empty() {
                self.active_bulk.push_back(flow_id);
                continue;
            }
            let bytes = cells.iter().map(ScheduledCellV2::len).sum::<usize>();
            flow.deficit -= bytes;
            self.depth.bulk_bytes -= bytes;
            let finished = cursor.cells.is_empty();
            let quantum = CellQuantum {
                class: TrafficClass::Bulk,
                priority: false,
                flow_id,
                train_id: cursor.train_id,
                cells,
                train_finished: finished,
                sojourn: cursor.enqueued.elapsed(),
                bulk_preemption: false,
                train_stats: cursor.stats.take(),
            };
            if finished {
                flow.trains.pop_front();
                self.depth.bulk_trains -= 1;
            }
            if flow.trains.is_empty() {
                self.bulk.remove(&flow_id);
                self.depth.bulk_flows -= 1;
            } else {
                self.active_bulk.push_back(flow_id);
            }
            self.record_quantum(&quantum);
            self.stats.bulk_quantum_count += 1;
            return Some(quantum);
        }
        None
    }

    fn record_quantum(&mut self, quantum: &CellQuantum) {
        let bytes = quantum.bytes();
        debug_assert!(quantum.cells.len() <= MAX_QUANTUM_CELLS);
        debug_assert!(bytes <= MAX_QUANTUM_BYTES);
        self.stats.quantum_count += 1;
        self.stats.quantum_bytes = self.stats.quantum_bytes.saturating_add(bytes as u64);
        self.stats.maximum_sojourn_micros = self
            .stats
            .maximum_sojourn_micros
            .max(quantum.sojourn.as_micros().min(u128::from(u64::MAX)) as u64);
    }

    fn enqueue_bytes(&mut self, bytes: Bytes, queue: TrafficQueue) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let (current, maximum) = match queue {
            TrafficQueue::Control => (&mut self.depth.control_bytes, self.limits.control_bytes),
            TrafficQueue::Probe => (&mut self.depth.probe_bytes, self.limits.probe_bytes),
        };
        if current.saturating_add(bytes.len()) > maximum {
            self.reject(bytes.len());
            return false;
        }
        *current += bytes.len();
        match queue {
            TrafficQueue::Control => self.control.push_back(bytes),
            TrafficQueue::Probe => self.probes.push_back(bytes),
        }
        true
    }

    fn evict_bulk_elastic(&mut self) -> bool {
        let active = self.active_bulk.iter().copied().collect::<Vec<_>>();
        for flow_id in active.into_iter().rev() {
            let Some(flow) = self.bulk.get_mut(&flow_id) else {
                continue;
            };
            let Some(candidate) = flow.trains.back() else {
                continue;
            };
            if self.depth.bulk_bytes.saturating_sub(candidate.bytes)
                < self.limits.bulk_reserve_bytes
            {
                continue;
            }
            let removed = flow.trains.pop_back().expect("checked non-empty");
            self.depth.bulk_bytes -= removed.bytes;
            self.depth.bulk_trains -= 1;
            self.stats.bulk_evicted_bytes = self
                .stats
                .bulk_evicted_bytes
                .saturating_add(removed.bytes as u64);
            if flow.trains.is_empty() {
                self.bulk.remove(&flow_id);
                self.active_bulk.retain(|candidate| *candidate != flow_id);
                self.depth.bulk_flows -= 1;
            }
            return true;
        }
        false
    }

    fn reject(&mut self, bytes: usize) {
        self.stats.rejected_bytes = self.stats.rejected_bytes.saturating_add(bytes as u64);
    }
}

#[derive(Debug, Clone, Copy)]
enum TrafficQueue {
    Control,
    Probe,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::train::{TrainContext, TrainRecord, build_packet_train};

    fn train(class: TrafficClass, train_id: u64, records: usize, bytes: usize) -> PacketTrain {
        build_packet_train(
            TrainContext {
                class,
                session_epoch: 1,
                route_label: 2,
                overlay_hop_limit: 64,
                train_id,
                maximum_datagram_size: 1382,
                maximum_cells: 256,
            },
            (1..=records).map(|record_id| TrainRecord {
                record_id: record_id as u16,
                metadata: Bytes::new(),
                data: Bytes::from(vec![record_id as u8; bytes]),
            }),
        )
        .unwrap()
    }

    #[test]
    fn hierarchy_is_control_latency_bulk_probe() {
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        scheduler.enqueue_probe(Bytes::from_static(b"probe"));
        scheduler
            .enqueue_train(2, train(TrafficClass::Bulk, 2, 1, 100), 1382)
            .unwrap();
        scheduler
            .enqueue_train(1, train(TrafficClass::Latency, 1, 1, 100), 1382)
            .unwrap();
        scheduler.enqueue_control(Bytes::from_static(b"control"));
        assert!(matches!(scheduler.pop(), Some(ScheduledWork::Control(_))));
        assert!(matches!(
            scheduler.pop(),
            Some(ScheduledWork::Cells(CellQuantum {
                class: TrafficClass::Latency,
                ..
            }))
        ));
        assert!(matches!(
            scheduler.pop(),
            Some(ScheduledWork::Cells(CellQuantum {
                class: TrafficClass::Bulk,
                ..
            }))
        ));
        assert!(matches!(scheduler.pop(), Some(ScheduledWork::Probe(_))));
    }

    #[test]
    fn bulk_train_pauses_at_a_hard_quantum_boundary() {
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        assert!(scheduler.set_bulk_quantum_cells(8).is_ok());
        assert!(scheduler.set_bulk_quantum_cells(9).is_err());
        scheduler
            .enqueue_train(1, train(TrafficClass::Bulk, 1, 44, 1500), 1382)
            .unwrap();
        let first = match scheduler.pop().unwrap() {
            ScheduledWork::Cells(quantum) => quantum,
            _ => panic!("expected cells"),
        };
        assert!((6..=8).contains(&first.cells.len()));
        assert!(first.cells.iter().all(|cell| cell.len() >= 1_300));
        assert!(first.bytes() <= MAX_QUANTUM_BYTES);
        assert!(!first.train_finished);

        scheduler
            .enqueue_train(2, train(TrafficClass::Latency, 2, 1, 64), 1382)
            .unwrap();
        let next = match scheduler.pop().unwrap() {
            ScheduledWork::Cells(quantum) => quantum,
            _ => panic!("expected cells"),
        };
        assert_eq!(next.class, TrafficClass::Latency);
        assert!(next.bulk_preemption);
        assert_eq!(scheduler.stats().bulk_preemptions, 1);
    }

    #[test]
    fn local_train_build_stats_are_reported_once() {
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        let train = train(TrafficClass::Bulk, 81, 12, 1_500);
        let expected = train.stats;
        scheduler.enqueue_train(1, train, 1_382).unwrap();

        let mut quanta = 0;
        let mut reports = Vec::new();
        while let Some(ScheduledWork::Cells(quantum)) = scheduler.pop() {
            quanta += 1;
            if let Some(stats) = quantum.train_stats {
                reports.push(stats);
            }
        }
        assert!(quanta > 1);
        assert_eq!(reports, vec![expected]);
    }

    #[test]
    fn local_one_segment_cell_keeps_record_data_as_a_split_tail() {
        let train = train(TrafficClass::Bulk, 91, 1, 1200);
        let expected = train.cells[0].encode(1382).unwrap();
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        assert!(scheduler.enqueue_train(7, train, 1382).unwrap());
        let ScheduledWork::Cells(quantum) = scheduler.pop().unwrap() else {
            panic!("expected Cell quantum");
        };
        assert_eq!(quantum.cells.len(), 1);
        let (head, tail) = quantum.cells[0].payload.parts();
        assert!(!tail.is_empty());
        let mut flattened = head.to_vec();
        flattened.extend_from_slice(tail);
        assert_eq!(flattened, expected);
        assert_eq!(
            quantum.cells[0].header,
            CellRouteHeaderV2::decode(&expected).unwrap()
        );
    }

    #[test]
    fn multi_segment_cell_stays_contiguous() {
        let train = train(TrafficClass::Bulk, 92, 2, 32);
        assert_eq!(train.cells.len(), 1);
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        assert!(scheduler.enqueue_train(8, train, 1382).unwrap());
        let ScheduledWork::Cells(quantum) = scheduler.pop().unwrap() else {
            panic!("expected Cell quantum");
        };
        let (_, tail) = quantum.cells[0].payload.parts();
        assert!(tail.is_empty());
    }

    #[test]
    fn drr_serves_each_backlogged_bulk_flow() {
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        for flow in 1..=8 {
            scheduler
                .enqueue_train(flow, train(TrafficClass::Bulk, flow, 16, 1200), 1382)
                .unwrap();
        }
        let mut first_round = Vec::new();
        let mut first_round_quantum_cells = Vec::new();
        for _ in 0..8 {
            let ScheduledWork::Cells(quantum) = scheduler.pop().unwrap() else {
                panic!("expected bulk cells");
            };
            first_round.push(quantum.flow_id);
            first_round_quantum_cells.push(quantum.cells.len());
        }
        first_round.sort_unstable();
        assert_eq!(first_round, (1..=8).collect::<Vec<_>>());
        assert!(
            first_round_quantum_cells
                .into_iter()
                .all(|cells| (6..=8).contains(&cells))
        );
    }

    #[test]
    fn sustained_latency_cannot_starve_bulk() {
        let limits = SchedulerLimits {
            latency_burst_bytes: 1,
            ..SchedulerLimits::default()
        };
        let mut scheduler = V2Scheduler::new(limits).unwrap();
        scheduler
            .enqueue_train(1, train(TrafficClass::Bulk, 1, 2, 1200), 1382)
            .unwrap();
        for id in 2..=8 {
            scheduler
                .enqueue_train(id, train(TrafficClass::Latency, id, 1, 100), 1382)
                .unwrap();
        }
        let ScheduledWork::Cells(first) = scheduler.pop().unwrap() else {
            panic!("expected latency");
        };
        assert_eq!(first.class, TrafficClass::Latency);
        let ScheduledWork::Cells(second) = scheduler.pop().unwrap() else {
            panic!("expected forced bulk");
        };
        assert_eq!(second.class, TrafficClass::Bulk);
        assert_eq!(scheduler.stats().bulk_forced_service, 1);
    }

    #[test]
    fn latency_uses_earliest_deadline_first() {
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        let now = Instant::now();
        scheduler
            .enqueue_train_with_deadline(
                1,
                train(TrafficClass::Latency, 1, 1, 100),
                1382,
                Some(now + Duration::from_secs(1)),
            )
            .unwrap();
        assert!(!scheduler.has_strict_urgent());
        scheduler
            .enqueue_train_with_deadline(
                2,
                train(TrafficClass::Latency, 2, 1, 100),
                1382,
                Some(now + Duration::from_millis(10)),
            )
            .unwrap();
        let ScheduledWork::Cells(quantum) = scheduler.pop().unwrap() else {
            panic!("expected cells");
        };
        assert_eq!(quantum.flow_id, 2);
    }

    #[test]
    fn strict_latency_tier_preempts_already_expired_best_effort_latency() {
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        let now = Instant::now();
        scheduler
            .enqueue_train_with_scheduling(
                1,
                train(TrafficClass::Latency, 1, 1, 1200),
                1382,
                Some(now - Duration::from_secs(1)),
                false,
            )
            .unwrap();
        scheduler
            .enqueue_train_with_scheduling(
                2,
                train(TrafficClass::Latency, 2, 1, 100),
                1382,
                Some(now),
                true,
            )
            .unwrap();
        assert!(scheduler.has_strict_urgent());

        let ScheduledWork::Cells(quantum) = scheduler.pop().unwrap() else {
            panic!("expected strict latency cells");
        };
        assert_eq!(quantum.flow_id, 2);
    }

    #[test]
    fn latency_can_reclaim_only_bulk_elastic_memory() {
        let sample = train(TrafficClass::Bulk, 1, 1, 1200);
        let sample_bytes = sample.stats.cell_wire_bytes as usize;
        let limits = SchedulerLimits {
            latency_bytes: sample_bytes * 2,
            bulk_bytes: sample_bytes * 3,
            application_bytes: sample_bytes * 3,
            bulk_reserve_bytes: sample_bytes,
            ..SchedulerLimits::default()
        };
        let mut scheduler = V2Scheduler::new(limits).unwrap();
        for id in 1..=3 {
            scheduler
                .enqueue_train(id, train(TrafficClass::Bulk, id, 1, 1200), 1382)
                .unwrap();
        }
        assert!(
            scheduler
                .enqueue_train(9, train(TrafficClass::Latency, 9, 1, 1200), 1382)
                .unwrap()
        );
        assert_eq!(scheduler.depth().bulk_bytes, sample_bytes * 2);
        assert_eq!(scheduler.stats().bulk_evicted_bytes, sample_bytes as u64);
    }

    #[test]
    fn transit_admission_parses_only_the_fixed_routing_shim() {
        let packet_train = train(TrafficClass::Bulk, 77, 1, 1200);
        let mut encoded = packet_train.cells[0]
            .encode(1382)
            .unwrap()
            .try_into_mut()
            .unwrap();
        // 36 is the first Record kind byte. It is deliberately invalid: a
        // transit hop must preserve it without decoding the Record payload.
        encoded[36] = 0xff;
        assert!(CellV2::decode(encoded.clone().freeze()).is_err());

        let expected = encoded.freeze();
        let mut scheduler = V2Scheduler::new(SchedulerLimits::default()).unwrap();
        assert!(
            scheduler
                .enqueue_forwarded_cells(9, vec![expected.clone()])
                .unwrap()
        );
        let ScheduledWork::Cells(quantum) = scheduler.pop().unwrap() else {
            panic!("expected transit Cell");
        };
        assert_eq!(quantum.flow_id, 9);
        assert_eq!(quantum.train_id, 77);
        assert_eq!(quantum.cells.len(), 1);
        let (head, tail) = quantum.cells[0].payload.parts();
        assert_eq!(head, &expected);
        assert!(tail.is_empty());
    }
}
