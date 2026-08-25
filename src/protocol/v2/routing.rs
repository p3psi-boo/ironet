use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use arc_swap::ArcSwap;
use bytes::{BufMut, Bytes, BytesMut};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

use super::cell::{CellRouteHeaderV2, ForwardedCellV2, advance_overlay_hop};

const MAGIC: &[u8; 4] = b"RAV2";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 16;
const ENTRY_LEN: usize = 20;
pub const MAX_ADVERTISED_PREFIXES: usize = 256;
pub const MAX_ROUTE_LABELS: usize = 65_536;
pub const MAX_CANDIDATE_ROUTES: usize = 4;
const MAX_RETIRED_SNAPSHOTS: usize = 2;

const OAM_MAGIC: &[u8; 4] = b"OEV2";
const OAM_VERSION: u8 = 1;
const OAM_TTL_EXPIRED: u8 = 1;
const OAM_PATH_MTU_EXCEEDED: u8 = 2;
const OAM_TTL_EXPIRED_LEN: usize = 72;
const OAM_PATH_MTU_EXCEEDED_LEN: usize = 76;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdjacencyIdV2(pub u32);

impl AdjacencyIdV2 {
    pub fn new(value: u32) -> Result<Self> {
        ensure!(value != 0, "V2 adjacency ID zero is reserved");
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteLabelV2(pub u32);

impl RouteLabelV2 {
    pub fn new(value: u32) -> Result<Self> {
        ensure!(value != 0, "V2 route label zero is reserved");
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolvedRouteV2 {
    pub adjacency: AdjacencyIdV2,
    pub route_label: RouteLabelV2,
    pub route_epoch: u32,
    /// Minimum authenticated DATAGRAM ceiling across every adjacency in the
    /// compiled path. Sources build Cells once at this end-to-end PMTU; a
    /// transit hop never fragments or reassembles them.
    pub maximum_datagram_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixRouteV2 {
    pub prefix: IpNet,
    pub route: ResolvedRouteV2,
    /// Sum of authenticated adjacency RTT costs for this compiled path.
    pub startup_latency: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelActionV2 {
    /// The Cell belongs to this node and may enter FEC/reassembly/TUN output.
    Local { expected_ingress: AdjacencyIdV2 },
    /// Forward the encoded Cell as-is after changing only its two-byte overlay
    /// hop accounting shim.
    Forward {
        expected_ingress: AdjacencyIdV2,
        next_hop: AdjacencyIdV2,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelRouteV2 {
    pub route_label: RouteLabelV2,
    pub route_epoch: u32,
    pub action: LabelActionV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitDropReasonV2 {
    UnderlayDestination,
    NoRoute,
    UnknownLabel,
    StaleRouteEpoch,
    UnexpectedIngress,
    ImmediateReflection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitDispositionV2 {
    Local {
        header: CellRouteHeaderV2,
        cell: Bytes,
    },
    Forward {
        next_hop: AdjacencyIdV2,
        cell: ForwardedCellV2,
    },
    TtlExpired(OamTtlExpiredV2),
    Drop(TransitDropReasonV2),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OamTtlExpiredV2 {
    pub snapshot_generation: u64,
    pub route_epoch: u32,
    pub route_label: RouteLabelV2,
    pub train_id: u64,
    pub cell_sequence: u16,
    pub ingress_hop_limit: u8,
    pub traversed_hops: u8,
    pub incoming: AdjacencyIdV2,
    pub reporter: [u8; 32],
}

impl OamTtlExpiredV2 {
    pub fn encode(&self) -> Result<Bytes> {
        self.validate()?;
        let mut out = BytesMut::with_capacity(OAM_TTL_EXPIRED_LEN);
        out.extend_from_slice(OAM_MAGIC);
        out.put_u8(OAM_VERSION);
        out.put_u8(OAM_TTL_EXPIRED);
        out.put_u16(0);
        out.put_u64(self.snapshot_generation);
        out.put_u32(self.route_epoch);
        out.put_u32(self.route_label.0);
        out.put_u64(self.train_id);
        out.put_u16(self.cell_sequence);
        out.put_u8(self.ingress_hop_limit);
        out.put_u8(self.traversed_hops);
        out.put_u32(self.incoming.0);
        out.extend_from_slice(&self.reporter);
        debug_assert_eq!(out.len(), OAM_TTL_EXPIRED_LEN);
        Ok(out.freeze())
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(bytes.len() == OAM_TTL_EXPIRED_LEN, "invalid V2 OAM length");
        ensure!(&bytes[..4] == OAM_MAGIC, "invalid V2 OAM magic");
        ensure!(bytes[4] == OAM_VERSION, "unsupported V2 OAM version");
        ensure!(bytes[5] == OAM_TTL_EXPIRED, "unsupported V2 OAM reason");
        ensure!(bytes[6..8] == [0, 0], "non-zero V2 OAM reserved field");
        let value = Self {
            snapshot_generation: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            route_epoch: u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
            route_label: RouteLabelV2(u32::from_be_bytes(bytes[20..24].try_into().unwrap())),
            train_id: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            cell_sequence: u16::from_be_bytes(bytes[32..34].try_into().unwrap()),
            ingress_hop_limit: bytes[34],
            traversed_hops: bytes[35],
            incoming: AdjacencyIdV2(u32::from_be_bytes(bytes[36..40].try_into().unwrap())),
            reporter: <[u8; 32]>::try_from(&bytes[40..72]).unwrap(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn is_record(bytes: &[u8]) -> bool {
        bytes.starts_with(OAM_MAGIC)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.snapshot_generation != 0,
            "V2 OAM generation zero is reserved"
        );
        ensure!(self.route_epoch != 0, "V2 OAM route epoch zero is reserved");
        RouteLabelV2::new(self.route_label.0)?;
        AdjacencyIdV2::new(self.incoming.0)?;
        ensure!(self.train_id != 0, "V2 OAM train ID zero is reserved");
        ensure!(
            self.ingress_hop_limit != 0,
            "V2 OAM ingress hop limit is zero"
        );
        ensure!(
            self.traversed_hops >= self.ingress_hop_limit,
            "V2 TTL-expired OAM was emitted before expiry"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OamPathMtuExceededV2 {
    pub snapshot_generation: u64,
    pub route_epoch: u32,
    pub route_label: RouteLabelV2,
    pub train_id: u64,
    pub cell_sequence: u16,
    pub observed_datagram_size: u16,
    pub maximum_datagram_size: u16,
    pub incoming: AdjacencyIdV2,
    pub reporter: [u8; 32],
}

impl OamPathMtuExceededV2 {
    pub fn encode(&self) -> Result<Bytes> {
        self.validate()?;
        let mut out = BytesMut::with_capacity(OAM_PATH_MTU_EXCEEDED_LEN);
        out.extend_from_slice(OAM_MAGIC);
        out.put_u8(OAM_VERSION);
        out.put_u8(OAM_PATH_MTU_EXCEEDED);
        out.put_u16(0);
        out.put_u64(self.snapshot_generation);
        out.put_u32(self.route_epoch);
        out.put_u32(self.route_label.0);
        out.put_u64(self.train_id);
        out.put_u16(self.cell_sequence);
        out.put_u16(self.observed_datagram_size);
        out.put_u16(self.maximum_datagram_size);
        out.put_u16(0);
        out.put_u32(self.incoming.0);
        out.extend_from_slice(&self.reporter);
        debug_assert_eq!(out.len(), OAM_PATH_MTU_EXCEEDED_LEN);
        Ok(out.freeze())
    }

    fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(
            bytes.len() == OAM_PATH_MTU_EXCEEDED_LEN,
            "invalid V2 path-MTU OAM length"
        );
        ensure!(&bytes[..4] == OAM_MAGIC, "invalid V2 OAM magic");
        ensure!(bytes[4] == OAM_VERSION, "unsupported V2 OAM version");
        ensure!(
            bytes[5] == OAM_PATH_MTU_EXCEEDED,
            "unsupported V2 OAM reason"
        );
        ensure!(bytes[6..8] == [0, 0], "non-zero V2 OAM reserved field");
        ensure!(
            bytes[38..40] == [0, 0],
            "non-zero V2 path-MTU OAM reserved field"
        );
        let value = Self {
            snapshot_generation: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            route_epoch: u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
            route_label: RouteLabelV2(u32::from_be_bytes(bytes[20..24].try_into().unwrap())),
            train_id: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            cell_sequence: u16::from_be_bytes(bytes[32..34].try_into().unwrap()),
            observed_datagram_size: u16::from_be_bytes(bytes[34..36].try_into().unwrap()),
            maximum_datagram_size: u16::from_be_bytes(bytes[36..38].try_into().unwrap()),
            incoming: AdjacencyIdV2(u32::from_be_bytes(bytes[40..44].try_into().unwrap())),
            reporter: <[u8; 32]>::try_from(&bytes[44..76]).unwrap(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.snapshot_generation != 0,
            "V2 path-MTU OAM generation zero is reserved"
        );
        ensure!(
            self.route_epoch != 0,
            "V2 path-MTU OAM route epoch zero is reserved"
        );
        RouteLabelV2::new(self.route_label.0)?;
        AdjacencyIdV2::new(self.incoming.0)?;
        ensure!(
            self.train_id != 0,
            "V2 path-MTU OAM train ID zero is reserved"
        );
        ensure!(
            self.maximum_datagram_size as usize > super::cell::HEADER_LEN,
            "V2 path-MTU OAM ceiling is too small"
        );
        ensure!(
            self.observed_datagram_size > self.maximum_datagram_size,
            "V2 path-MTU OAM did not exceed the path ceiling"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OamControlV2 {
    TtlExpired(OamTtlExpiredV2),
    PathMtuExceeded(OamPathMtuExceededV2),
}

impl OamControlV2 {
    pub fn is_record(bytes: &[u8]) -> bool {
        bytes.starts_with(OAM_MAGIC)
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(bytes.len() >= 6, "truncated V2 OAM record");
        ensure!(&bytes[..4] == OAM_MAGIC, "invalid V2 OAM magic");
        ensure!(bytes[4] == OAM_VERSION, "unsupported V2 OAM version");
        match bytes[5] {
            OAM_TTL_EXPIRED => OamTtlExpiredV2::decode(bytes).map(Self::TtlExpired),
            OAM_PATH_MTU_EXCEEDED => OamPathMtuExceededV2::decode(bytes).map(Self::PathMtuExceeded),
            _ => bail!("unsupported V2 OAM reason"),
        }
    }
}

/// Immutable, precompiled data-plane view. Prefix lookup only occurs on flow
/// admission; every transit Cell uses the hash label table directly.
#[derive(Debug, Clone)]
pub struct DataplaneSnapshotV2 {
    generation: u64,
    local_node: [u8; 32],
    prefixes_v4: Vec<PrefixRouteV2>,
    prefixes_v6: Vec<PrefixRouteV2>,
    underlay_exclusion_prefixes: Vec<IpNet>,
    labels: HashMap<RouteLabelV2, LabelRouteV2>,
    source_routes: HashMap<(u32, RouteLabelV2), ResolvedRouteV2>,
}

impl DataplaneSnapshotV2 {
    pub fn compile(
        generation: u64,
        local_node: [u8; 32],
        prefixes: Vec<PrefixRouteV2>,
        labels: Vec<LabelRouteV2>,
        underlay_exclusion_prefixes: Vec<IpNet>,
        allow_default_routes: bool,
    ) -> Result<Self> {
        ensure!(generation != 0, "V2 snapshot generation zero is reserved");
        ensure!(labels.len() <= MAX_ROUTE_LABELS, "too many V2 route labels");
        validate_prefix_set(
            underlay_exclusion_prefixes.iter(),
            true,
            "underlay exclusion",
        )?;

        let mut label_map = HashMap::default();
        for entry in labels {
            RouteLabelV2::new(entry.route_label.0)?;
            ensure!(entry.route_epoch != 0, "V2 route epoch zero is reserved");
            match entry.action {
                LabelActionV2::Local { expected_ingress } => {
                    AdjacencyIdV2::new(expected_ingress.0)?;
                }
                LabelActionV2::Forward {
                    expected_ingress,
                    next_hop,
                } => {
                    AdjacencyIdV2::new(expected_ingress.0)?;
                    AdjacencyIdV2::new(next_hop.0)?;
                    ensure!(
                        expected_ingress != next_hop,
                        "V2 route label immediately reflects to its ingress"
                    );
                }
            }
            ensure!(
                label_map.insert(entry.route_label, entry).is_none(),
                "duplicate V2 route label"
            );
        }

        let mut unique_prefixes = prefixes
            .iter()
            .map(|entry| entry.prefix)
            .collect::<Vec<_>>();
        unique_prefixes.sort_by_key(|prefix| (family(prefix), prefix.addr(), prefix.prefix_len()));
        unique_prefixes.dedup();
        validate_prefix_set(
            unique_prefixes.iter(),
            allow_default_routes,
            "overlay route",
        )?;
        for entry in &prefixes {
            AdjacencyIdV2::new(entry.route.adjacency.0)?;
            RouteLabelV2::new(entry.route.route_label.0)?;
            ensure!(
                entry.route.route_epoch != 0,
                "V2 route epoch zero is reserved"
            );
            ensure!(
                entry.route.maximum_datagram_size as usize > super::cell::HEADER_LEN,
                "V2 route DATAGRAM ceiling is too small"
            );
        }
        let mut source_routes = HashMap::default();
        for route in prefixes.iter().map(|entry| entry.route) {
            ensure!(
                source_routes
                    .insert((route.route_epoch, route.route_label), route)
                    .is_none(),
                "duplicate V2 source route label"
            );
        }

        let mut prefixes_v4 = prefixes
            .iter()
            .filter(|entry| entry.prefix.addr().is_ipv4())
            .cloned()
            .collect::<Vec<_>>();
        let mut prefixes_v6 = prefixes
            .into_iter()
            .filter(|entry| entry.prefix.addr().is_ipv6())
            .collect::<Vec<_>>();
        sort_longest_prefix_first(&mut prefixes_v4);
        sort_longest_prefix_first(&mut prefixes_v6);
        Ok(Self {
            generation,
            local_node,
            prefixes_v4,
            prefixes_v6,
            underlay_exclusion_prefixes,
            labels: label_map,
            source_routes,
        })
    }

    pub fn empty(generation: u64, local_node: [u8; 32]) -> Result<Self> {
        Self::compile(
            generation,
            local_node,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            false,
        )
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn route_count(&self) -> usize {
        self.prefixes_v4.len() + self.prefixes_v6.len()
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    pub fn label_action(
        &self,
        route_epoch: u32,
        route_label: RouteLabelV2,
    ) -> Option<LabelActionV2> {
        self.labels
            .get(&route_label)
            .filter(|entry| entry.route_epoch == route_epoch)
            .map(|entry| entry.action)
    }

    pub fn source_route(
        &self,
        route_epoch: u32,
        route_label: RouteLabelV2,
    ) -> Option<ResolvedRouteV2> {
        self.source_routes.get(&(route_epoch, route_label)).copied()
    }

    fn route_epochs(&self) -> HashSet<u32> {
        self.labels
            .values()
            .map(|entry| entry.route_epoch)
            .chain(
                self.source_routes
                    .keys()
                    .map(|(route_epoch, _)| *route_epoch),
            )
            .collect()
    }

    pub fn lookup_destination(
        &self,
        destination: IpAddr,
    ) -> std::result::Result<ResolvedRouteV2, TransitDropReasonV2> {
        if self
            .underlay_exclusion_prefixes
            .iter()
            .any(|prefix| prefix.contains(&destination))
        {
            return Err(TransitDropReasonV2::UnderlayDestination);
        }
        let routes = if destination.is_ipv4() {
            &self.prefixes_v4
        } else {
            &self.prefixes_v6
        };
        routes
            .iter()
            .find(|entry| entry.prefix.contains(&destination))
            .map(|entry| entry.route)
            .ok_or(TransitDropReasonV2::NoRoute)
    }

    pub fn lookup_destination_candidates(
        &self,
        destination: IpAddr,
    ) -> std::result::Result<Vec<(ResolvedRouteV2, Duration)>, TransitDropReasonV2> {
        if self
            .underlay_exclusion_prefixes
            .iter()
            .any(|prefix| prefix.contains(&destination))
        {
            return Err(TransitDropReasonV2::UnderlayDestination);
        }
        let routes = if destination.is_ipv4() {
            &self.prefixes_v4
        } else {
            &self.prefixes_v6
        };
        let prefix_len = routes
            .iter()
            .find(|entry| entry.prefix.contains(&destination))
            .map(|entry| entry.prefix.prefix_len())
            .ok_or(TransitDropReasonV2::NoRoute)?;
        Ok(routes
            .iter()
            .filter(|entry| {
                entry.prefix.prefix_len() == prefix_len && entry.prefix.contains(&destination)
            })
            .map(|entry| (entry.route, entry.startup_latency))
            .collect())
    }

    /// Resolve a received Cell through the O(1) label fast path. Local Cells
    /// remain untouched. Transit Cells advance only bytes 34..36 and retain
    /// the encoded Record/FEC payload verbatim.
    pub fn dispatch_cell(
        &self,
        incoming: AdjacencyIdV2,
        bytes: Bytes,
    ) -> Result<TransitDispositionV2> {
        AdjacencyIdV2::new(incoming.0)?;
        let header = CellRouteHeaderV2::decode(&bytes)?;
        let label = RouteLabelV2(header.route_label);
        let Some(entry) = self.labels.get(&label) else {
            return Ok(TransitDispositionV2::Drop(
                TransitDropReasonV2::UnknownLabel,
            ));
        };
        if entry.route_epoch != header.session_epoch {
            return Ok(TransitDispositionV2::Drop(
                TransitDropReasonV2::StaleRouteEpoch,
            ));
        }
        match entry.action {
            LabelActionV2::Local { expected_ingress } => {
                if incoming != expected_ingress {
                    return Ok(TransitDispositionV2::Drop(
                        TransitDropReasonV2::UnexpectedIngress,
                    ));
                }
                Ok(TransitDispositionV2::Local {
                    header,
                    cell: bytes,
                })
            }
            LabelActionV2::Forward {
                expected_ingress,
                next_hop,
            } => {
                if incoming != expected_ingress {
                    return Ok(TransitDispositionV2::Drop(
                        TransitDropReasonV2::UnexpectedIngress,
                    ));
                }
                if incoming == next_hop {
                    return Ok(TransitDispositionV2::Drop(
                        TransitDropReasonV2::ImmediateReflection,
                    ));
                }
                if header.overlay_hop_limit <= 1 {
                    return Ok(TransitDispositionV2::TtlExpired(OamTtlExpiredV2 {
                        snapshot_generation: self.generation,
                        route_epoch: entry.route_epoch,
                        route_label: label,
                        train_id: header.train_id,
                        cell_sequence: header.cell_sequence,
                        ingress_hop_limit: header.ingress_hop_limit(),
                        traversed_hops: header.overlay_hops.saturating_add(1),
                        incoming,
                        reporter: self.local_node,
                    }));
                }
                Ok(TransitDispositionV2::Forward {
                    next_hop,
                    cell: advance_overlay_hop(bytes)?,
                })
            }
        }
    }
}

/// ArcSwap publication point. The control plane is the sole writer; data
/// workers load one Arc per ingress batch and perform no route lock/scan after
/// a flow or label has been selected.
#[derive(Debug)]
struct SnapshotSetV2 {
    current: Arc<DataplaneSnapshotV2>,
    retired: Vec<Arc<DataplaneSnapshotV2>>,
}

#[derive(Debug)]
pub struct DataplaneSnapshotStoreV2 {
    generations: ArcSwap<SnapshotSetV2>,
}

impl DataplaneSnapshotStoreV2 {
    pub fn new(initial: DataplaneSnapshotV2) -> Self {
        Self {
            generations: ArcSwap::from_pointee(SnapshotSetV2 {
                current: Arc::new(initial),
                retired: Vec::new(),
            }),
        }
    }

    pub fn load(&self) -> Arc<DataplaneSnapshotV2> {
        self.generations.load().current.clone()
    }

    /// Publish from the single control-plane writer. Existing workers keep
    /// their old Arc until already-built PacketTrains naturally drain.
    pub fn publish(&self, next: DataplaneSnapshotV2) -> Result<Arc<DataplaneSnapshotV2>> {
        let generations = self.generations.load_full();
        let previous = generations.current.clone();
        ensure!(
            next.generation() > previous.generation(),
            "V2 snapshot generation did not advance"
        );
        let previous_epochs = previous.route_epochs();
        let next_epochs = next.route_epochs();
        ensure!(
            previous_epochs.is_disjoint(&next_epochs) || next_epochs.is_empty(),
            "V2 snapshot reused a live route epoch"
        );
        let mut retired = Vec::with_capacity(MAX_RETIRED_SNAPSHOTS);
        retired.push(previous.clone());
        retired.extend(
            generations
                .retired
                .iter()
                .take(MAX_RETIRED_SNAPSHOTS - 1)
                .cloned(),
        );
        self.generations.store(Arc::new(SnapshotSetV2 {
            current: Arc::new(next),
            retired,
        }));
        Ok(previous)
    }

    /// Current generation first, then at most two immutable drain generations
    /// only for unknown/stale labels. The common path remains one ArcSwap load
    /// and one hash lookup; in-flight old PacketTrains do not need a mutable
    /// label-lifetime table.
    pub fn dispatch_cell(
        &self,
        incoming: AdjacencyIdV2,
        bytes: Bytes,
    ) -> Result<TransitDispositionV2> {
        let generations = self.generations.load();
        let current = generations.current.dispatch_cell(incoming, bytes.clone())?;
        if !matches!(
            current,
            TransitDispositionV2::Drop(TransitDropReasonV2::UnknownLabel)
                | TransitDispositionV2::Drop(TransitDropReasonV2::StaleRouteEpoch)
        ) {
            return Ok(current);
        }
        for retired in &generations.retired {
            let disposition = retired.dispatch_cell(incoming, bytes.clone())?;
            if !matches!(
                disposition,
                TransitDispositionV2::Drop(TransitDropReasonV2::UnknownLabel)
                    | TransitDispositionV2::Drop(TransitDropReasonV2::StaleRouteEpoch)
            ) {
                return Ok(disposition);
            }
        }
        Ok(current)
    }

    /// Resolve reliable Repair/OAM records through the same current + drain
    /// generations as DATAGRAM labels. This is control-plane cold path, so a
    /// bounded scan of at most three immutable snapshots is preferable to a
    /// second mutable reverse-route table.
    pub fn label_action(
        &self,
        route_epoch: u32,
        route_label: RouteLabelV2,
    ) -> Option<LabelActionV2> {
        let generations = self.generations.load();
        generations
            .current
            .label_action(route_epoch, route_label)
            .or_else(|| {
                generations
                    .retired
                    .iter()
                    .find_map(|snapshot| snapshot.label_action(route_epoch, route_label))
            })
    }

    pub fn source_route(
        &self,
        route_epoch: u32,
        route_label: RouteLabelV2,
    ) -> Option<ResolvedRouteV2> {
        let generations = self.generations.load();
        generations
            .current
            .source_route(route_epoch, route_label)
            .or_else(|| {
                generations
                    .retired
                    .iter()
                    .find_map(|snapshot| snapshot.source_route(route_epoch, route_label))
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeIdV2(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyNodeV2 {
    pub node_id: NodeIdV2,
    pub advertised_prefixes: Vec<IpNet>,
    pub transit_enabled: bool,
    /// Destinations that must stay on the native network even when an overlay
    /// default route exists (peer locators, relay addresses, DNS/bootstrap).
    pub underlay_exclusion_prefixes: Vec<IpNet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologyLinkV2 {
    pub left: NodeIdV2,
    pub right: NodeIdV2,
    /// Local adjacency ID used by `left` when sending to `right`.
    pub left_adjacency: AdjacencyIdV2,
    /// Local adjacency ID used by `right` when sending to `left`.
    pub right_adjacency: AdjacencyIdV2,
    pub cost: u32,
    pub healthy: bool,
    pub maximum_datagram_size: u16,
}

#[derive(Debug, Clone)]
pub struct CompiledTopologyV2 {
    pub generation: u64,
    pub route_epoch: u32,
    pub snapshots: HashMap<NodeIdV2, DataplaneSnapshotV2>,
}

impl CompiledTopologyV2 {
    pub fn snapshot(&self, node: NodeIdV2) -> Option<&DataplaneSnapshotV2> {
        self.snapshots.get(&node)
    }
}

#[derive(Debug, Clone, Copy)]
struct DirectedLinkV2 {
    peer: NodeIdV2,
    adjacency: AdjacencyIdV2,
    cost: u32,
    maximum_datagram_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteDemandV2 {
    source: NodeIdV2,
    owner: NodeIdV2,
    prefix: IpNet,
}

#[derive(Debug, Default)]
struct SnapshotPartsV2 {
    prefixes: Vec<PrefixRouteV2>,
    labels: Vec<LabelRouteV2>,
}

/// Compile the same authenticated Presence/link generation into every node's
/// immutable view. A globally deterministic label is allocated per
/// `(source, owner, prefix)` path, so converging routes retain one expected
/// ingress at every hop and cannot reflect into a different source tree.
pub fn compile_topology_v2(
    generation: u64,
    route_epoch: u32,
    nodes: Vec<TopologyNodeV2>,
    links: Vec<TopologyLinkV2>,
    allow_default_routes: bool,
) -> Result<CompiledTopologyV2> {
    ensure!(generation != 0, "V2 topology generation zero is reserved");
    ensure!(route_epoch != 0, "V2 route epoch zero is reserved");
    ensure!(!nodes.is_empty(), "V2 topology has no nodes");

    let mut node_map = HashMap::default();
    for node in nodes {
        validate_prefix_set(
            node.advertised_prefixes.iter(),
            allow_default_routes,
            "advertised",
        )?;
        validate_prefix_set(
            node.underlay_exclusion_prefixes.iter(),
            true,
            "underlay exclusion",
        )?;
        ensure!(
            node_map.insert(node.node_id, node).is_none(),
            "duplicate V2 topology node"
        );
    }
    validate_global_ownership(&node_map)?;

    let mut graph = HashMap::<NodeIdV2, Vec<DirectedLinkV2>>::default();
    let mut adjacency_ids = HashSet::<(NodeIdV2, AdjacencyIdV2)>::default();
    let mut node_pairs = HashSet::<(NodeIdV2, NodeIdV2)>::default();
    for link in links {
        ensure!(link.left != link.right, "V2 topology link is a self-loop");
        ensure!(
            node_map.contains_key(&link.left) && node_map.contains_key(&link.right),
            "V2 topology link references an unknown node"
        );
        AdjacencyIdV2::new(link.left_adjacency.0)?;
        AdjacencyIdV2::new(link.right_adjacency.0)?;
        ensure!(link.cost != 0, "V2 topology link cost is zero");
        ensure!(
            link.maximum_datagram_size as usize > super::cell::HEADER_LEN,
            "V2 topology link DATAGRAM ceiling is too small"
        );
        ensure!(
            adjacency_ids.insert((link.left, link.left_adjacency))
                && adjacency_ids.insert((link.right, link.right_adjacency)),
            "duplicate V2 local adjacency ID"
        );
        let pair = if link.left < link.right {
            (link.left, link.right)
        } else {
            (link.right, link.left)
        };
        ensure!(node_pairs.insert(pair), "duplicate V2 topology link");
        if !link.healthy {
            continue;
        }
        graph.entry(link.left).or_default().push(DirectedLinkV2 {
            peer: link.right,
            adjacency: link.left_adjacency,
            cost: link.cost,
            maximum_datagram_size: link.maximum_datagram_size,
        });
        graph.entry(link.right).or_default().push(DirectedLinkV2 {
            peer: link.left,
            adjacency: link.right_adjacency,
            cost: link.cost,
            maximum_datagram_size: link.maximum_datagram_size,
        });
    }
    for edges in graph.values_mut() {
        edges.sort_by_key(|edge| (edge.cost, edge.peer, edge.adjacency));
    }

    let mut node_ids = node_map.keys().copied().collect::<Vec<_>>();
    node_ids.sort_unstable();
    let transit_nodes = node_map
        .values()
        .filter(|node| node.transit_enabled)
        .map(|node| node.node_id)
        .collect::<HashSet<_>>();
    let mut demands = Vec::new();
    for source in &node_ids {
        for owner in &node_ids {
            if source == owner {
                continue;
            }
            for prefix in &node_map[owner].advertised_prefixes {
                demands.push(RouteDemandV2 {
                    source: *source,
                    owner: *owner,
                    prefix: *prefix,
                });
            }
        }
    }
    demands.sort_by_key(|demand| {
        (
            demand.source,
            demand.owner,
            family(&demand.prefix),
            demand.prefix.addr(),
            demand.prefix.prefix_len(),
        )
    });
    let mut parts = node_ids
        .iter()
        .copied()
        .map(|node| (node, SnapshotPartsV2::default()))
        .collect::<HashMap<_, _>>();
    let mut next_route_label = 1_u32;
    for demand in demands {
        for path in candidate_paths_v2(demand.source, demand.owner, &graph, &transit_nodes) {
            ensure!(
                usize::try_from(next_route_label).unwrap_or(usize::MAX) <= MAX_ROUTE_LABELS,
                "V2 topology exceeds route-label capacity"
            );
            debug_assert!(path.len() >= 2);
            let route_label = RouteLabelV2::new(next_route_label)?;
            next_route_label = next_route_label
                .checked_add(1)
                .context("V2 route label overflow")?;
            let path_links = path
                .windows(2)
                .map(|hop| directed_link_v2(&graph, hop[0], hop[1]))
                .collect::<Result<Vec<_>>>()?;
            let first_hop = path_links[0];
            let startup_latency =
                Duration::from_micros(path_links.iter().map(|link| u64::from(link.cost)).sum());
            let maximum_datagram_size = path_links
                .iter()
                .map(|link| link.maximum_datagram_size)
                .min()
                .context("V2 compiled path has no adjacency")?;
            parts
                .get_mut(&demand.source)
                .expect("source topology parts exist")
                .prefixes
                .push(PrefixRouteV2 {
                    prefix: demand.prefix,
                    route: ResolvedRouteV2 {
                        adjacency: first_hop.adjacency,
                        route_label,
                        route_epoch,
                        maximum_datagram_size,
                    },
                    startup_latency,
                });
            for hop in 1..path.len() {
                let current = path[hop];
                let previous = path[hop - 1];
                let expected_ingress = directed_link_v2(&graph, current, previous)?.adjacency;
                let action = if hop + 1 == path.len() {
                    LabelActionV2::Local { expected_ingress }
                } else {
                    let next_hop = directed_link_v2(&graph, current, path[hop + 1])?.adjacency;
                    LabelActionV2::Forward {
                        expected_ingress,
                        next_hop,
                    }
                };
                parts
                    .get_mut(&current)
                    .expect("transit topology parts exist")
                    .labels
                    .push(LabelRouteV2 {
                        route_label,
                        route_epoch,
                        action,
                    });
            }
        }
    }

    let mut snapshots = HashMap::default();
    for node_id in node_ids {
        let node = &node_map[&node_id];
        let part = parts.remove(&node_id).expect("topology parts exist");
        let snapshot = DataplaneSnapshotV2::compile(
            generation,
            node_id.0,
            part.prefixes,
            part.labels,
            node.underlay_exclusion_prefixes.clone(),
            allow_default_routes,
        )?;
        snapshots.insert(node_id, snapshot);
    }
    Ok(CompiledTopologyV2 {
        generation,
        route_epoch,
        snapshots,
    })
}

fn validate_global_ownership(nodes: &HashMap<NodeIdV2, TopologyNodeV2>) -> Result<()> {
    let mut owned = Vec::new();
    for node in nodes.values() {
        for prefix in &node.advertised_prefixes {
            for (other_owner, other) in &owned {
                if node.node_id != *other_owner {
                    ensure!(
                        !prefixes_overlap(prefix, other),
                        "overlapping V2 advertised prefixes owned by {:?} and {:?}",
                        node.node_id,
                        other_owner
                    );
                }
            }
            owned.push((node.node_id, *prefix));
        }
    }
    Ok(())
}

fn prefixes_overlap(left: &IpNet, right: &IpNet) -> bool {
    left.addr().is_ipv4() == right.addr().is_ipv4()
        && (left.contains(&right.network()) || right.contains(&left.network()))
}

fn directed_link_v2(
    graph: &HashMap<NodeIdV2, Vec<DirectedLinkV2>>,
    from: NodeIdV2,
    to: NodeIdV2,
) -> Result<DirectedLinkV2> {
    graph
        .get(&from)
        .and_then(|edges| edges.iter().find(|edge| edge.peer == to))
        .copied()
        .ok_or_else(|| anyhow::anyhow!("V2 compiled path references an absent healthy link"))
}

fn shortest_path_excluding_v2(
    source: NodeIdV2,
    destination: NodeIdV2,
    excluded: Option<NodeIdV2>,
    graph: &HashMap<NodeIdV2, Vec<DirectedLinkV2>>,
    transit_nodes: &HashSet<NodeIdV2>,
) -> Option<Vec<NodeIdV2>> {
    let mut distance = HashMap::<NodeIdV2, u64>::default();
    let mut previous = HashMap::<NodeIdV2, NodeIdV2>::default();
    let mut visited = HashSet::default();
    distance.insert(source, 0);
    loop {
        let current = distance
            .iter()
            .filter(|(node, _)| Some(**node) != excluded && !visited.contains(*node))
            .min_by_key(|(node, cost)| (**cost, **node))
            .map(|(node, cost)| (*node, *cost));
        let (current, current_cost) = current?;
        if current == destination {
            break;
        }
        visited.insert(current);
        if current != source && !transit_nodes.contains(&current) {
            continue;
        }
        for edge in graph.get(&current).into_iter().flatten() {
            if Some(edge.peer) == excluded || visited.contains(&edge.peer) {
                continue;
            }
            let candidate = current_cost.saturating_add(u64::from(edge.cost));
            let replace = match distance.get(&edge.peer) {
                None => true,
                Some(existing) if candidate < *existing => true,
                Some(existing) if candidate == *existing => previous
                    .get(&edge.peer)
                    .is_none_or(|old_previous| current < *old_previous),
                Some(_) => false,
            };
            if replace {
                distance.insert(edge.peer, candidate);
                previous.insert(edge.peer, current);
            }
        }
    }
    let mut path = vec![destination];
    while *path.last()? != source {
        path.push(*previous.get(path.last()?)?);
    }
    path.reverse();
    Some(path)
}

/// Keep one deterministic loop-free path per usable first hop. This gives the
/// source enough alternatives for demand-aware selection without turning the
/// label table into an all-paths combinatorial expansion.
fn candidate_paths_v2(
    source: NodeIdV2,
    destination: NodeIdV2,
    graph: &HashMap<NodeIdV2, Vec<DirectedLinkV2>>,
    transit_nodes: &HashSet<NodeIdV2>,
) -> Vec<Vec<NodeIdV2>> {
    let mut candidates = Vec::new();
    for edge in graph.get(&source).into_iter().flatten() {
        let path = if edge.peer == destination {
            Some(vec![source, destination])
        } else if transit_nodes.contains(&edge.peer) {
            shortest_path_excluding_v2(edge.peer, destination, Some(source), graph, transit_nodes)
                .map(|tail| {
                    let mut path = Vec::with_capacity(tail.len() + 1);
                    path.push(source);
                    path.extend(tail);
                    path
                })
        } else {
            None
        };
        if let Some(path) = path {
            candidates.push(path);
        }
    }
    candidates.sort_by_key(|path| {
        let cost = path.windows(2).fold(0_u64, |total, hop| {
            total.saturating_add(
                directed_link_v2(graph, hop[0], hop[1])
                    .map_or(u64::MAX, |link| u64::from(link.cost)),
            )
        });
        (cost, path.clone())
    });
    candidates.truncate(MAX_CANDIDATE_ROUTES);
    candidates
}

fn validate_prefix_set<'a>(
    prefixes: impl IntoIterator<Item = &'a IpNet>,
    allow_default_routes: bool,
    kind: &str,
) -> Result<()> {
    let mut canonical = prefixes.into_iter().copied().collect::<Vec<_>>();
    for prefix in &canonical {
        ensure!(
            prefix.addr() == prefix.network(),
            "non-canonical V2 {kind} prefix"
        );
        ensure!(
            allow_default_routes || prefix.prefix_len() != 0,
            "V2 default route was not explicitly enabled"
        );
    }
    canonical.sort_by_key(|prefix| (family(prefix), prefix.addr(), prefix.prefix_len()));
    let count = canonical.len();
    canonical.dedup();
    ensure!(canonical.len() == count, "duplicate V2 {kind} prefix");
    Ok(())
}

fn sort_longest_prefix_first(routes: &mut [PrefixRouteV2]) {
    routes.sort_by(|left, right| {
        right
            .prefix
            .prefix_len()
            .cmp(&left.prefix.prefix_len())
            .then_with(|| left.prefix.addr().cmp(&right.prefix.addr()))
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdvertisementV2 {
    pub generation: u64,
    pub prefixes: Vec<IpNet>,
}

impl RouteAdvertisementV2 {
    pub fn encode(&self) -> Result<Bytes> {
        self.validate(true)?;
        let mut out = BytesMut::with_capacity(HEADER_LEN + self.prefixes.len() * ENTRY_LEN);
        out.extend_from_slice(MAGIC);
        out.put_u8(VERSION);
        out.put_u8(0);
        out.put_u16(self.prefixes.len() as u16);
        out.put_u64(self.generation);
        for prefix in &self.prefixes {
            match prefix {
                IpNet::V4(prefix) => {
                    out.put_u8(4);
                    out.put_u8(prefix.prefix_len());
                    out.put_u16(0);
                    out.extend_from_slice(&prefix.network().octets());
                    out.extend_from_slice(&[0; 12]);
                }
                IpNet::V6(prefix) => {
                    out.put_u8(6);
                    out.put_u8(prefix.prefix_len());
                    out.put_u16(0);
                    out.extend_from_slice(&prefix.network().octets());
                }
            }
        }
        Ok(out.freeze())
    }

    pub fn decode(bytes: Bytes, allow_default_routes: bool) -> Result<Self> {
        ensure!(
            bytes.len() >= HEADER_LEN,
            "truncated V2 route advertisement"
        );
        ensure!(&bytes[..4] == MAGIC, "invalid V2 route advertisement magic");
        ensure!(
            bytes[4] == VERSION,
            "unsupported V2 route advertisement version"
        );
        ensure!(bytes[5] == 0, "unsupported V2 route advertisement flags");
        let count = usize::from(u16::from_be_bytes(bytes[6..8].try_into().unwrap()));
        ensure!(
            count <= MAX_ADVERTISED_PREFIXES && bytes.len() == HEADER_LEN + count * ENTRY_LEN,
            "invalid V2 route advertisement length"
        );
        let generation = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let mut prefixes = Vec::with_capacity(count);
        for entry in bytes[HEADER_LEN..].as_chunks::<ENTRY_LEN>().0 {
            ensure!(entry[2..4] == [0, 0], "non-zero V2 route reserved field");
            let prefix = match entry[0] {
                4 => {
                    ensure!(entry[1] <= 32, "invalid V2 IPv4 prefix length");
                    ensure!(entry[8..20] == [0; 12], "invalid V2 IPv4 padding");
                    IpNet::V4(Ipv4Net::new(
                        Ipv4Addr::new(entry[4], entry[5], entry[6], entry[7]),
                        entry[1],
                    )?)
                }
                6 => {
                    ensure!(entry[1] <= 128, "invalid V2 IPv6 prefix length");
                    IpNet::V6(Ipv6Net::new(
                        Ipv6Addr::from(<[u8; 16]>::try_from(&entry[4..20]).unwrap()),
                        entry[1],
                    )?)
                }
                _ => anyhow::bail!("invalid V2 route address family"),
            };
            prefixes.push(prefix);
        }
        let advertisement = Self {
            generation,
            prefixes,
        };
        advertisement.validate(allow_default_routes)?;
        Ok(advertisement)
    }

    pub fn is_record(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC)
    }

    pub fn validate(&self, allow_default_routes: bool) -> Result<()> {
        ensure!(self.generation != 0, "V2 route generation zero is reserved");
        ensure!(
            self.prefixes.len() <= MAX_ADVERTISED_PREFIXES,
            "too many V2 advertised prefixes"
        );
        let mut canonical = self.prefixes.clone();
        canonical.sort_by_key(|prefix| (family(prefix), prefix.addr(), prefix.prefix_len()));
        canonical.dedup();
        ensure!(
            canonical.len() == self.prefixes.len(),
            "duplicate V2 advertised prefix"
        );
        for prefix in &self.prefixes {
            ensure!(
                prefix.addr() == prefix.network(),
                "non-canonical V2 advertised prefix"
            );
            ensure!(
                allow_default_routes || prefix.prefix_len() != 0,
                "V2 default route was not explicitly enabled"
            );
            ensure!(
                !prefix.addr().is_unspecified() || prefix.prefix_len() == 0,
                "invalid V2 unspecified advertised prefix"
            );
        }
        Ok(())
    }
}

fn family(prefix: &IpNet) -> u8 {
    match prefix.addr() {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::cell::{CellBody, CellV2, RecordSegment, SegmentKind, TrafficClass};

    fn adjacency(value: u32) -> AdjacencyIdV2 {
        AdjacencyIdV2::new(value).unwrap()
    }

    fn label(value: u32) -> RouteLabelV2 {
        RouteLabelV2::new(value).unwrap()
    }

    fn encoded_cell(route_label: u32, route_epoch: u32, hop_limit: u8) -> Bytes {
        CellV2 {
            class: TrafficClass::Bulk,
            flags: 0,
            session_epoch: route_epoch,
            route_label,
            train_id: 99,
            cell_sequence: 4,
            stripe_id: 0,
            overlay_hop_limit: hop_limit,
            overlay_hops: 0,
            body: CellBody::Records(vec![RecordSegment {
                kind: SegmentKind::Full,
                flags: 0,
                record_id: 1,
                total_len: 3,
                offset: 0,
                metadata: Bytes::new(),
                data: Bytes::from_static(b"abc"),
            }]),
        }
        .encode(1382)
        .unwrap()
    }

    fn snapshot(generation: u64, narrow_adjacency: u32) -> DataplaneSnapshotV2 {
        let direct_epoch = u32::try_from(generation * 2 + 5).unwrap();
        let narrow_epoch = direct_epoch + 1;
        let direct = LabelRouteV2 {
            route_label: label(10),
            route_epoch: direct_epoch,
            action: LabelActionV2::Local {
                expected_ingress: adjacency(1),
            },
        };
        let narrow = LabelRouteV2 {
            route_label: label(11),
            route_epoch: narrow_epoch,
            action: LabelActionV2::Forward {
                expected_ingress: adjacency(1),
                next_hop: adjacency(narrow_adjacency),
            },
        };
        DataplaneSnapshotV2::compile(
            generation,
            [generation as u8; 32],
            vec![
                PrefixRouteV2 {
                    prefix: "10.0.0.0/8".parse().unwrap(),
                    route: ResolvedRouteV2 {
                        adjacency: adjacency(2),
                        route_label: label(10),
                        route_epoch: direct_epoch,
                        maximum_datagram_size: 1_382,
                    },
                    startup_latency: Duration::from_millis(10),
                },
                PrefixRouteV2 {
                    prefix: "10.1.0.0/16".parse().unwrap(),
                    route: ResolvedRouteV2 {
                        adjacency: adjacency(narrow_adjacency),
                        route_label: label(11),
                        route_epoch: narrow_epoch,
                        maximum_datagram_size: 1_382,
                    },
                    startup_latency: Duration::from_millis(20),
                },
            ],
            vec![direct, narrow],
            vec!["10.1.2.3/32".parse().unwrap()],
            false,
        )
        .unwrap()
    }

    fn node(value: u8, prefixes: &[&str]) -> TopologyNodeV2 {
        TopologyNodeV2 {
            node_id: NodeIdV2([value; 32]),
            advertised_prefixes: prefixes
                .iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect(),
            transit_enabled: true,
            underlay_exclusion_prefixes: Vec::new(),
        }
    }

    fn three_node_links(direct_cost: u32, direct_healthy: bool) -> Vec<TopologyLinkV2> {
        vec![
            TopologyLinkV2 {
                left: NodeIdV2([1; 32]),
                right: NodeIdV2([2; 32]),
                left_adjacency: adjacency(12),
                right_adjacency: adjacency(21),
                cost: 1,
                healthy: true,
                maximum_datagram_size: 1_382,
            },
            TopologyLinkV2 {
                left: NodeIdV2([2; 32]),
                right: NodeIdV2([3; 32]),
                left_adjacency: adjacency(23),
                right_adjacency: adjacency(32),
                cost: 1,
                healthy: true,
                maximum_datagram_size: 1_200,
            },
            TopologyLinkV2 {
                left: NodeIdV2([1; 32]),
                right: NodeIdV2([3; 32]),
                left_adjacency: adjacency(13),
                right_adjacency: adjacency(31),
                cost: direct_cost,
                healthy: direct_healthy,
                maximum_datagram_size: 1_300,
            },
        ]
    }

    #[test]
    fn advertisement_round_trips_canonical_dual_stack_prefixes() {
        let advertisement = RouteAdvertisementV2 {
            generation: 7,
            prefixes: vec![
                "11.6.1.0/24".parse().unwrap(),
                "fd12:3456::/48".parse().unwrap(),
            ],
        };
        assert_eq!(
            RouteAdvertisementV2::decode(advertisement.encode().unwrap(), false).unwrap(),
            advertisement
        );
    }

    #[test]
    fn advertisement_rejects_duplicates_defaults_and_malformed_entries() {
        let duplicate = RouteAdvertisementV2 {
            generation: 1,
            prefixes: vec!["10.0.0.0/8".parse().unwrap(), "10.0.0.0/8".parse().unwrap()],
        };
        assert!(duplicate.encode().is_err());
        let default = RouteAdvertisementV2 {
            generation: 1,
            prefixes: vec!["0.0.0.0/0".parse().unwrap()],
        };
        let bytes = default.encode().unwrap();
        assert!(RouteAdvertisementV2::decode(bytes.clone(), false).is_err());
        assert!(RouteAdvertisementV2::decode(bytes, true).is_ok());
    }

    #[test]
    fn snapshot_uses_longest_prefix_and_excludes_underlay_endpoints() {
        let snapshot = snapshot(1, 3);
        assert_eq!(snapshot.route_count(), 2);
        assert_eq!(snapshot.label_count(), 2);
        assert_eq!(
            snapshot
                .lookup_destination("10.1.9.9".parse().unwrap())
                .unwrap()
                .route_label,
            label(11)
        );
        assert_eq!(
            snapshot
                .lookup_destination("10.9.9.9".parse().unwrap())
                .unwrap()
                .route_label,
            label(10)
        );
        assert_eq!(
            snapshot.lookup_destination("10.1.2.3".parse().unwrap()),
            Err(TransitDropReasonV2::UnderlayDestination)
        );
    }

    #[test]
    fn label_fast_path_forwards_without_record_or_fec_decode() {
        let snapshot = snapshot(1, 3);
        let disposition = snapshot
            .dispatch_cell(adjacency(1), encoded_cell(11, 8, 6))
            .unwrap();
        let TransitDispositionV2::Forward { next_hop, cell } = disposition else {
            panic!("expected transit forwarding");
        };
        assert_eq!(next_hop, adjacency(3));
        assert_eq!(cell.header.overlay_hop_limit, 5);
        assert_eq!(cell.header.overlay_hops, 1);
        let decoded = CellV2::decode(cell.bytes).unwrap();
        let CellBody::Records(records) = decoded.body else {
            panic!("transit changed Cell kind");
        };
        assert_eq!(records[0].data, Bytes::from_static(b"abc"));
    }

    #[test]
    fn label_fast_path_rejects_wrong_ingress_epoch_and_reflection() {
        let snapshot = snapshot(1, 3);
        assert_eq!(
            snapshot
                .dispatch_cell(adjacency(2), encoded_cell(11, 8, 6))
                .unwrap(),
            TransitDispositionV2::Drop(TransitDropReasonV2::UnexpectedIngress)
        );
        assert_eq!(
            snapshot
                .dispatch_cell(adjacency(1), encoded_cell(11, 9, 6))
                .unwrap(),
            TransitDispositionV2::Drop(TransitDropReasonV2::StaleRouteEpoch)
        );

        assert!(
            DataplaneSnapshotV2::compile(
                2,
                [0; 32],
                Vec::new(),
                vec![LabelRouteV2 {
                    route_label: label(4),
                    route_epoch: 1,
                    action: LabelActionV2::Forward {
                        expected_ingress: adjacency(7),
                        next_hop: adjacency(7),
                    },
                }],
                Vec::new(),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn ttl_expiry_emits_strict_oam_record() {
        let snapshot = snapshot(5, 3);
        let disposition = snapshot
            .dispatch_cell(adjacency(1), encoded_cell(11, 16, 1))
            .unwrap();
        let TransitDispositionV2::TtlExpired(oam) = disposition else {
            panic!("expected TTL-expired OAM");
        };
        assert_eq!(oam.snapshot_generation, 5);
        assert_eq!(oam.ingress_hop_limit, 1);
        assert_eq!(oam.traversed_hops, 1);
        assert_eq!(oam.reporter, [5; 32]);
        assert_eq!(OamTtlExpiredV2::decode(oam.encode().unwrap()).unwrap(), oam);
    }

    #[test]
    fn path_mtu_oam_round_trips_and_rejects_non_exceeding_cells() {
        let oam = OamPathMtuExceededV2 {
            snapshot_generation: 7,
            route_epoch: 9,
            route_label: label(11),
            train_id: 42,
            cell_sequence: 3,
            observed_datagram_size: 1_382,
            maximum_datagram_size: 1_200,
            incoming: adjacency(21),
            reporter: [2; 32],
        };
        assert_eq!(
            OamControlV2::decode(oam.encode().unwrap()).unwrap(),
            OamControlV2::PathMtuExceeded(oam.clone())
        );
        let mut invalid = oam;
        invalid.observed_datagram_size = invalid.maximum_datagram_size;
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn snapshot_publication_is_atomic_and_old_generation_drains() {
        let first = snapshot(1, 3);
        let store = DataplaneSnapshotStoreV2::new(first);
        let old_worker_view = store.load();
        let retired = store.publish(snapshot(2, 4)).unwrap();
        assert_eq!(old_worker_view.generation(), 1);
        assert_eq!(retired.generation(), 1);
        assert_eq!(
            old_worker_view
                .lookup_destination("10.1.9.9".parse().unwrap())
                .unwrap()
                .adjacency,
            adjacency(3)
        );
        assert_eq!(
            store
                .load()
                .lookup_destination("10.1.9.9".parse().unwrap())
                .unwrap()
                .adjacency,
            adjacency(4)
        );
        let draining = store
            .dispatch_cell(adjacency(1), encoded_cell(11, 8, 6))
            .unwrap();
        assert!(matches!(
            draining,
            TransitDispositionV2::Forward {
                next_hop: AdjacencyIdV2(3),
                ..
            }
        ));
        store.publish(snapshot(3, 5)).unwrap();
        assert!(matches!(
            store
                .dispatch_cell(adjacency(1), encoded_cell(11, 8, 6))
                .unwrap(),
            TransitDispositionV2::Forward { .. }
        ));
        store.publish(snapshot(4, 6)).unwrap();
        assert!(matches!(
            store
                .dispatch_cell(adjacency(1), encoded_cell(11, 8, 6))
                .unwrap(),
            TransitDispositionV2::Drop(TransitDropReasonV2::StaleRouteEpoch)
        ));
        assert!(store.publish(snapshot(2, 5)).is_err());
    }

    #[test]
    fn defaults_require_opt_in_and_outbound_labels_need_no_local_action() {
        let route = PrefixRouteV2 {
            prefix: "0.0.0.0/0".parse().unwrap(),
            route: ResolvedRouteV2 {
                adjacency: adjacency(2),
                route_label: label(1),
                route_epoch: 1,
                maximum_datagram_size: 1_382,
            },
            startup_latency: Duration::from_millis(1),
        };
        let label_route = LabelRouteV2 {
            route_label: label(1),
            route_epoch: 1,
            action: LabelActionV2::Local {
                expected_ingress: adjacency(2),
            },
        };
        assert!(
            DataplaneSnapshotV2::compile(
                1,
                [0; 32],
                vec![route.clone()],
                vec![label_route],
                Vec::new(),
                false,
            )
            .is_err()
        );
        assert!(
            DataplaneSnapshotV2::compile(
                1,
                [0; 32],
                vec![route],
                vec![label_route],
                Vec::new(),
                true,
            )
            .is_ok()
        );
        assert!(
            DataplaneSnapshotV2::compile(
                2,
                [0; 32],
                vec![PrefixRouteV2 {
                    prefix: "192.0.2.0/24".parse().unwrap(),
                    route: ResolvedRouteV2 {
                        adjacency: adjacency(2),
                        route_label: label(99),
                        route_epoch: 2,
                        maximum_datagram_size: 1_382,
                    },
                    startup_latency: Duration::from_millis(1),
                }],
                Vec::new(),
                Vec::new(),
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn topology_compiler_builds_end_to_end_transit_label_without_presence_scans() {
        let topology = compile_topology_v2(
            9,
            42,
            vec![node(1, &[]), node(2, &[]), node(3, &["11.6.1.0/24"])],
            three_node_links(10, true),
            false,
        )
        .unwrap();
        let a = topology.snapshot(NodeIdV2([1; 32])).unwrap();
        let b = topology.snapshot(NodeIdV2([2; 32])).unwrap();
        let c = topology.snapshot(NodeIdV2([3; 32])).unwrap();
        let route = a.lookup_destination("11.6.1.48".parse().unwrap()).unwrap();
        assert_eq!(route.adjacency, adjacency(12));
        assert_eq!(route.route_epoch, 42);
        assert_eq!(route.maximum_datagram_size, 1_200);

        let at_b = b
            .dispatch_cell(adjacency(21), encoded_cell(route.route_label.0, 42, 2))
            .unwrap();
        let TransitDispositionV2::Forward { next_hop, cell } = at_b else {
            panic!("B must transit the Cell");
        };
        assert_eq!(next_hop, adjacency(23));
        assert_eq!(cell.header.overlay_hop_limit, 1);
        let at_c = c.dispatch_cell(adjacency(32), cell.bytes).unwrap();
        assert!(matches!(at_c, TransitDispositionV2::Local { .. }));
        // B's own first packets have a prefix route, while A's already-labeled
        // Cells enter the separate O(1) label table.
        assert_eq!(b.route_count(), 2);
        assert_eq!(b.label_count(), 1);
    }

    #[test]
    fn topology_prefers_healthy_direct_owner_then_falls_back_to_transit() {
        let nodes = vec![node(1, &[]), node(2, &[]), node(3, &["11.6.1.0/24"])];
        let direct =
            compile_topology_v2(1, 1, nodes.clone(), three_node_links(1, true), false).unwrap();
        let direct_route = direct
            .snapshot(NodeIdV2([1; 32]))
            .unwrap()
            .lookup_destination("11.6.1.48".parse().unwrap())
            .unwrap();
        assert_eq!(direct_route.adjacency, adjacency(13));
        assert_eq!(direct_route.maximum_datagram_size, 1_300);
        let candidates = direct
            .snapshot(NodeIdV2([1; 32]))
            .unwrap()
            .lookup_destination_candidates("11.6.1.48".parse().unwrap())
            .unwrap();
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|(route, _)| route.adjacency == adjacency(12))
        );
        assert_eq!(direct.snapshot(NodeIdV2([2; 32])).unwrap().label_count(), 1);

        let transit = compile_topology_v2(2, 2, nodes, three_node_links(1, false), false).unwrap();
        let transit_route = transit
            .snapshot(NodeIdV2([1; 32]))
            .unwrap()
            .lookup_destination("11.6.1.48".parse().unwrap())
            .unwrap();
        assert_eq!(transit_route.adjacency, adjacency(12));
        assert_eq!(transit_route.maximum_datagram_size, 1_200);
        assert_eq!(
            transit.snapshot(NodeIdV2([2; 32])).unwrap().label_count(),
            1
        );
    }

    #[test]
    fn topology_labels_are_deterministic_and_ownership_is_unambiguous() {
        let nodes = vec![
            node(1, &["10.1.0.0/16"]),
            node(2, &[]),
            node(3, &["11.6.1.0/24"]),
        ];
        let links = three_node_links(10, true);
        let first = compile_topology_v2(1, 7, nodes.clone(), links.clone(), false).unwrap();
        let second = compile_topology_v2(
            1,
            7,
            nodes.into_iter().rev().collect(),
            links.into_iter().rev().collect(),
            false,
        )
        .unwrap();
        let destination = "11.6.1.48".parse().unwrap();
        assert_eq!(
            first
                .snapshot(NodeIdV2([1; 32]))
                .unwrap()
                .lookup_destination(destination),
            second
                .snapshot(NodeIdV2([1; 32]))
                .unwrap()
                .lookup_destination(destination)
        );

        assert!(
            compile_topology_v2(
                2,
                8,
                vec![node(1, &["10.0.0.0/8"]), node(2, &["10.1.0.0/16"])],
                vec![TopologyLinkV2 {
                    left: NodeIdV2([1; 32]),
                    right: NodeIdV2([2; 32]),
                    left_adjacency: adjacency(1),
                    right_adjacency: adjacency(2),
                    cost: 1,
                    healthy: true,
                    maximum_datagram_size: 1_382,
                }],
                false,
            )
            .is_err()
        );
        assert!(
            compile_topology_v2(
                3,
                9,
                vec![node(1, &[]), node(2, &["10.0.0.0/8", "10.1.0.0/16"]),],
                vec![TopologyLinkV2 {
                    left: NodeIdV2([1; 32]),
                    right: NodeIdV2([2; 32]),
                    left_adjacency: adjacency(1),
                    right_adjacency: adjacency(2),
                    cost: 1,
                    healthy: true,
                    maximum_datagram_size: 1_382,
                }],
                false,
            )
            .is_ok()
        );
    }
}
