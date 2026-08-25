use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iroh::{EndpointId, SecretKey};
use iroh_base::Signature;
use rustc_hash::FxHashMap as HashMap;

use super::routing::{
    AdjacencyIdV2, CompiledTopologyV2, DataplaneSnapshotV2, NodeIdV2, TopologyLinkV2,
    TopologyNodeV2, compile_local_snapshot_v2, compile_topology_v2,
};

const MAGIC: &[u8; 4] = b"PRV2";
const VERSION: u8 = 2;
const FLAG_TRANSIT: u8 = 1;
const HEADER_LEN: usize = 104;
const ADDRESS_LEN: usize = 20;
const PREFIX_LEN: usize = 20;
const LINK_LEN: usize = 40;
const TRAILER_LEN: usize = 96;
pub const MAX_PRESENCE_BYTES: usize = 64 * 1024;
pub const MAX_DIRECT_ADDRESSES: usize = 8;
pub const MAX_NODE_ADDRESSES: usize = 2;
pub const MAX_PRESENCE_PREFIXES: usize = 256;
pub const MAX_PRESENCE_LINKS: usize = 256;
pub const DIRECTORY_CAPACITY: usize = 4_096;
pub const MAX_PRESENCE_TTL: Duration = Duration::from_secs(600);
const CLOCK_SKEW: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceLinkV2 {
    pub peer: EndpointId,
    pub cost: u32,
    pub healthy: bool,
    pub maximum_datagram_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceBodyV2 {
    pub owner: EndpointId,
    pub sequence: u64,
    pub issued_unix_secs: u64,
    pub expires_unix_secs: u64,
    pub direct_addresses: Vec<SocketAddr>,
    pub node_addresses: Vec<IpNet>,
    pub prefixes: Vec<IpNet>,
    pub links: Vec<PresenceLinkV2>,
    pub transit_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPresenceV2 {
    pub body: PresenceBodyV2,
    pub network_fingerprint: [u8; 32],
    pub signature: Signature,
    pub membership_tag: [u8; 32],
}

impl SignedPresenceV2 {
    pub fn sign(
        mut body: PresenceBodyV2,
        secret_key: &SecretKey,
        network_id: &str,
    ) -> Result<Self> {
        ensure!(
            body.owner == secret_key.public(),
            "V2 Presence owner does not match signing key"
        );
        canonicalize_body(&mut body);
        validate_body(&body, None)?;
        ensure!(is_canonical(&body), "duplicate V2 Presence entry");
        let network_fingerprint = network_fingerprint(network_id);
        let unsigned = encode_unsigned(&body, network_fingerprint)?;
        let signature = secret_key.sign(&unsigned);
        let membership_tag = membership_tag(network_id, &unsigned, &signature);
        Ok(Self {
            body,
            network_fingerprint,
            signature,
            membership_tag,
        })
    }

    pub fn encode(&self) -> Result<Bytes> {
        validate_body(&self.body, None)?;
        ensure!(is_canonical(&self.body), "non-canonical V2 Presence body");
        let unsigned = encode_unsigned(&self.body, self.network_fingerprint)?;
        let length = unsigned
            .len()
            .checked_add(TRAILER_LEN)
            .context("V2 Presence length overflow")?;
        ensure!(
            length <= MAX_PRESENCE_BYTES,
            "V2 Presence exceeds wire limit"
        );
        let mut out = BytesMut::with_capacity(length);
        out.extend_from_slice(&unsigned);
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(&self.membership_tag);
        Ok(out.freeze())
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(
            (HEADER_LEN + TRAILER_LEN..=MAX_PRESENCE_BYTES).contains(&bytes.len()),
            "invalid V2 Presence length"
        );
        ensure!(&bytes[..4] == MAGIC, "invalid V2 Presence magic");
        ensure!(bytes[4] == VERSION, "unsupported V2 Presence version");
        ensure!(
            bytes[5] & !FLAG_TRANSIT == 0,
            "unsupported V2 Presence flags"
        );
        let address_count = usize::from(u16::from_be_bytes(bytes[6..8].try_into().unwrap()));
        let prefix_count = usize::from(u16::from_be_bytes(bytes[8..10].try_into().unwrap()));
        let link_count = usize::from(u16::from_be_bytes(bytes[10..12].try_into().unwrap()));
        let node_address_count = usize::from(u16::from_be_bytes(bytes[12..14].try_into().unwrap()));
        ensure!(
            bytes[14..16] == [0; 2],
            "non-zero V2 Presence reserved field"
        );
        ensure!(
            address_count <= MAX_DIRECT_ADDRESSES
                && node_address_count <= MAX_NODE_ADDRESSES
                && prefix_count <= MAX_PRESENCE_PREFIXES
                && link_count <= MAX_PRESENCE_LINKS,
            "V2 Presence count exceeds limit"
        );
        let variable = address_count
            .checked_mul(ADDRESS_LEN)
            .and_then(|value| value.checked_add(node_address_count * PREFIX_LEN))
            .and_then(|value| value.checked_add(prefix_count * PREFIX_LEN))
            .and_then(|value| value.checked_add(link_count * LINK_LEN))
            .context("V2 Presence length overflow")?;
        let unsigned_len = HEADER_LEN + variable;
        ensure!(
            bytes.len() == unsigned_len + TRAILER_LEN,
            "invalid V2 Presence encoded length"
        );
        let owner = EndpointId::from_bytes(&<[u8; 32]>::try_from(&bytes[40..72]).unwrap())
            .context("invalid V2 Presence owner")?;
        let network_fingerprint = <[u8; 32]>::try_from(&bytes[72..104]).unwrap();
        let mut cursor = HEADER_LEN;
        let mut direct_addresses = Vec::with_capacity(address_count);
        for _ in 0..address_count {
            direct_addresses.push(decode_address(&bytes[cursor..cursor + ADDRESS_LEN])?);
            cursor += ADDRESS_LEN;
        }
        let mut node_addresses = Vec::with_capacity(node_address_count);
        for _ in 0..node_address_count {
            node_addresses.push(decode_prefix(&bytes[cursor..cursor + PREFIX_LEN])?);
            cursor += PREFIX_LEN;
        }
        let mut prefixes = Vec::with_capacity(prefix_count);
        for _ in 0..prefix_count {
            prefixes.push(decode_prefix(&bytes[cursor..cursor + PREFIX_LEN])?);
            cursor += PREFIX_LEN;
        }
        let mut links = Vec::with_capacity(link_count);
        for _ in 0..link_count {
            let entry = &bytes[cursor..cursor + LINK_LEN];
            ensure!(entry[39] == 0, "non-zero V2 Presence link reserved field");
            ensure!(entry[36] & !1 == 0, "unsupported V2 Presence link flags");
            links.push(PresenceLinkV2 {
                peer: EndpointId::from_bytes(&<[u8; 32]>::try_from(&entry[..32]).unwrap())
                    .context("invalid V2 Presence link peer")?,
                cost: u32::from_be_bytes(entry[32..36].try_into().unwrap()),
                healthy: entry[36] != 0,
                maximum_datagram_size: u16::from_be_bytes(entry[37..39].try_into().unwrap()),
            });
            cursor += LINK_LEN;
        }
        let signature = Signature::from_bytes(
            &<[u8; 64]>::try_from(&bytes[unsigned_len..unsigned_len + 64]).unwrap(),
        );
        let membership_tag =
            <[u8; 32]>::try_from(&bytes[unsigned_len + 64..unsigned_len + 96]).unwrap();
        let value = Self {
            body: PresenceBodyV2 {
                owner,
                sequence: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
                issued_unix_secs: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
                expires_unix_secs: u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
                direct_addresses,
                node_addresses,
                prefixes,
                links,
                transit_enabled: bytes[5] & FLAG_TRANSIT != 0,
            },
            network_fingerprint,
            signature,
            membership_tag,
        };
        validate_body(&value.body, None)?;
        ensure!(is_canonical(&value.body), "non-canonical V2 Presence body");
        Ok(value)
    }

    pub fn verify(&self, network_id: &str, now: SystemTime) -> Result<()> {
        validate_body(&self.body, Some(unix_secs(now)?))?;
        ensure!(is_canonical(&self.body), "non-canonical V2 Presence body");
        ensure!(
            self.network_fingerprint == network_fingerprint(network_id),
            "V2 Presence belongs to another network"
        );
        let unsigned = encode_unsigned(&self.body, self.network_fingerprint)?;
        self.body
            .owner
            .verify(&unsigned, &self.signature)
            .context("invalid V2 Presence owner signature")?;
        ensure!(
            constant_time_eq(
                &self.membership_tag,
                &membership_tag(network_id, &unsigned, &self.signature)
            ),
            "invalid V2 Presence membership proof"
        );
        Ok(())
    }

    pub fn is_record(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceUpdateV2 {
    Inserted,
    Replaced,
    /// Only the lease sequence, timestamps, and authentication changed. The
    /// fields consumed by topology compilation are identical.
    Renewed,
    Duplicate,
    Stale,
}

#[derive(Debug, Clone)]
pub struct PresenceDirectoryV2 {
    network_id: String,
    records: HashMap<EndpointId, SignedPresenceV2>,
}

impl PresenceDirectoryV2 {
    pub fn new(network_id: String) -> Result<Self> {
        ensure!(!network_id.is_empty(), "V2 Presence network ID is empty");
        Ok(Self {
            network_id,
            records: HashMap::default(),
        })
    }

    pub fn insert(
        &mut self,
        presence: SignedPresenceV2,
        now: SystemTime,
    ) -> Result<PresenceUpdateV2> {
        presence.verify(&self.network_id, now)?;
        let owner = presence.body.owner;
        let update = match self.records.get(&owner) {
            Some(current) if presence.body.sequence < current.body.sequence => {
                return Ok(PresenceUpdateV2::Stale);
            }
            Some(current) if presence.body.sequence == current.body.sequence => {
                ensure!(
                    current == &presence,
                    "conflicting V2 Presence sequence replay"
                );
                return Ok(PresenceUpdateV2::Duplicate);
            }
            Some(current) if same_topology(&current.body, &presence.body) => {
                PresenceUpdateV2::Renewed
            }
            Some(_) => PresenceUpdateV2::Replaced,
            None => PresenceUpdateV2::Inserted,
        };
        self.prune(now)?;
        while self.records.len() >= DIRECTORY_CAPACITY && !self.records.contains_key(&owner) {
            let oldest = self
                .records
                .iter()
                .min_by_key(|(_, record)| (record.body.expires_unix_secs, record.body.sequence))
                .map(|(owner, _)| *owner)
                .context("V2 Presence directory capacity accounting failed")?;
            self.records.remove(&oldest);
        }
        self.records.insert(owner, presence);
        Ok(update)
    }

    pub fn prune(&mut self, now: SystemTime) -> Result<usize> {
        let now = unix_secs(now)?;
        let before = self.records.len();
        self.records
            .retain(|_, record| record.body.expires_unix_secs > now);
        Ok(before - self.records.len())
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> impl Iterator<Item = &SignedPresenceV2> {
        self.records.values()
    }

    /// Accept a link only when both fresh owners advertise each other. This
    /// prevents one endpoint from inventing a third-party adjacency.
    pub fn compile_topology(
        &mut self,
        generation: u64,
        route_epoch: u32,
        allow_default_routes: bool,
        now: SystemTime,
    ) -> Result<CompiledTopologyV2> {
        let (nodes, links) = self.topology_input(now)?;
        compile_topology_v2(generation, route_epoch, nodes, links, allow_default_routes)
    }

    pub fn compile_local_snapshot(
        &mut self,
        generation: u64,
        route_epoch: u32,
        allow_default_routes: bool,
        local_node: NodeIdV2,
        now: SystemTime,
    ) -> Result<DataplaneSnapshotV2> {
        let (nodes, links) = self.topology_input(now)?;
        compile_local_snapshot_v2(
            generation,
            route_epoch,
            nodes,
            links,
            allow_default_routes,
            local_node,
        )
    }

    fn topology_input(
        &mut self,
        now: SystemTime,
    ) -> Result<(Vec<TopologyNodeV2>, Vec<TopologyLinkV2>)> {
        self.prune(now)?;
        ensure!(!self.records.is_empty(), "V2 Presence directory is empty");
        let mut exclusions = self
            .records
            .values()
            .flat_map(|record| {
                record
                    .body
                    .direct_addresses
                    .iter()
                    .map(|address| address.ip())
            })
            .map(host_prefix)
            .collect::<Vec<_>>();
        exclusions
            .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
        exclusions.dedup();
        let nodes = self
            .records
            .values()
            .map(|record| TopologyNodeV2 {
                node_id: NodeIdV2(*record.body.owner.as_bytes()),
                advertised_prefixes: record
                    .body
                    .node_addresses
                    .iter()
                    .chain(&record.body.prefixes)
                    .copied()
                    .collect(),
                transit_enabled: record.body.transit_enabled,
                underlay_exclusion_prefixes: exclusions.clone(),
            })
            .collect::<Vec<_>>();
        let mut links = Vec::new();
        let mut owners = self.records.keys().copied().collect::<Vec<_>>();
        owners.sort_unstable();
        for (index, left_id) in owners.iter().copied().enumerate() {
            for right_id in owners.iter().copied().skip(index + 1) {
                let left = &self.records[&left_id].body;
                let right = &self.records[&right_id].body;
                let Some(left_link) = left.links.iter().find(|link| link.peer == right_id) else {
                    continue;
                };
                let Some(right_link) = right.links.iter().find(|link| link.peer == left_id) else {
                    continue;
                };
                if !left_link.healthy || !right_link.healthy {
                    continue;
                }
                links.push(TopologyLinkV2 {
                    left: NodeIdV2(*left_id.as_bytes()),
                    right: NodeIdV2(*right_id.as_bytes()),
                    left_adjacency: adjacency_id(left_id, right_id),
                    right_adjacency: adjacency_id(right_id, left_id),
                    cost: left_link.cost.max(right_link.cost),
                    healthy: true,
                    maximum_datagram_size: left_link
                        .maximum_datagram_size
                        .min(right_link.maximum_datagram_size),
                });
            }
        }
        Ok((nodes, links))
    }
}

fn same_topology(current: &PresenceBodyV2, next: &PresenceBodyV2) -> bool {
    current.owner == next.owner
        && current.direct_addresses == next.direct_addresses
        && current.node_addresses == next.node_addresses
        && current.prefixes == next.prefixes
        && current.links == next.links
        && current.transit_enabled == next.transit_enabled
}

pub fn adjacency_id(local: EndpointId, peer: EndpointId) -> AdjacencyIdV2 {
    let mut hasher = blake3::Hasher::new_derive_key("ironet v2 local adjacency id");
    hasher.update(local.as_bytes());
    hasher.update(peer.as_bytes());
    let mut value = u32::from_be_bytes(hasher.finalize().as_bytes()[..4].try_into().unwrap());
    if value == 0 {
        value = 1;
    }
    AdjacencyIdV2(value)
}

fn encode_unsigned(body: &PresenceBodyV2, fingerprint: [u8; 32]) -> Result<Bytes> {
    validate_body(body, None)?;
    let length = HEADER_LEN
        .checked_add(body.direct_addresses.len() * ADDRESS_LEN)
        .and_then(|value| value.checked_add(body.node_addresses.len() * PREFIX_LEN))
        .and_then(|value| value.checked_add(body.prefixes.len() * PREFIX_LEN))
        .and_then(|value| value.checked_add(body.links.len() * LINK_LEN))
        .context("V2 Presence length overflow")?;
    ensure!(
        length + TRAILER_LEN <= MAX_PRESENCE_BYTES,
        "V2 Presence exceeds wire limit"
    );
    let mut out = BytesMut::with_capacity(length);
    out.extend_from_slice(MAGIC);
    out.put_u8(VERSION);
    out.put_u8(u8::from(body.transit_enabled) * FLAG_TRANSIT);
    out.put_u16(body.direct_addresses.len() as u16);
    out.put_u16(body.prefixes.len() as u16);
    out.put_u16(body.links.len() as u16);
    out.put_u16(body.node_addresses.len() as u16);
    out.put_u16(0);
    out.put_u64(body.sequence);
    out.put_u64(body.issued_unix_secs);
    out.put_u64(body.expires_unix_secs);
    out.extend_from_slice(body.owner.as_bytes());
    out.extend_from_slice(&fingerprint);
    for address in &body.direct_addresses {
        encode_address(&mut out, *address);
    }
    for address in &body.node_addresses {
        encode_prefix(&mut out, *address);
    }
    for prefix in &body.prefixes {
        encode_prefix(&mut out, *prefix);
    }
    for link in &body.links {
        out.extend_from_slice(link.peer.as_bytes());
        out.put_u32(link.cost);
        out.put_u8(u8::from(link.healthy));
        out.put_u16(link.maximum_datagram_size);
        out.put_u8(0);
    }
    debug_assert_eq!(out.len(), length);
    Ok(out.freeze())
}

fn encode_address(out: &mut BytesMut, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            out.put_u8(4);
            out.put_u8(0);
            out.put_u16(address.port());
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&[0; 12]);
        }
        IpAddr::V6(ip) => {
            out.put_u8(6);
            out.put_u8(0);
            out.put_u16(address.port());
            out.extend_from_slice(&ip.octets());
        }
    }
}

fn decode_address(entry: &[u8]) -> Result<SocketAddr> {
    ensure!(
        entry.len() == ADDRESS_LEN,
        "invalid V2 Presence address length"
    );
    ensure!(entry[1] == 0, "non-zero V2 Presence address reserved field");
    let port = u16::from_be_bytes(entry[2..4].try_into().unwrap());
    let ip = match entry[0] {
        4 => {
            ensure!(entry[8..20] == [0; 12], "invalid V2 Presence IPv4 padding");
            IpAddr::V4(Ipv4Addr::new(entry[4], entry[5], entry[6], entry[7]))
        }
        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&entry[4..20]).unwrap())),
        _ => anyhow::bail!("invalid V2 Presence address family"),
    };
    Ok(SocketAddr::new(ip, port))
}

fn encode_prefix(out: &mut BytesMut, prefix: IpNet) {
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

fn decode_prefix(entry: &[u8]) -> Result<IpNet> {
    ensure!(
        entry.len() == PREFIX_LEN,
        "invalid V2 Presence prefix length"
    );
    ensure!(
        entry[2..4] == [0, 0],
        "non-zero V2 Presence prefix reserved field"
    );
    Ok(match entry[0] {
        4 => {
            ensure!(entry[1] <= 32, "invalid V2 Presence IPv4 prefix length");
            ensure!(entry[8..20] == [0; 12], "invalid V2 Presence IPv4 padding");
            IpNet::V4(Ipv4Net::new(
                Ipv4Addr::new(entry[4], entry[5], entry[6], entry[7]),
                entry[1],
            )?)
        }
        6 => {
            ensure!(entry[1] <= 128, "invalid V2 Presence IPv6 prefix length");
            IpNet::V6(Ipv6Net::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&entry[4..20]).unwrap()),
                entry[1],
            )?)
        }
        _ => anyhow::bail!("invalid V2 Presence prefix family"),
    })
}

fn validate_body(body: &PresenceBodyV2, now: Option<u64>) -> Result<()> {
    ensure!(body.sequence != 0, "V2 Presence sequence zero is reserved");
    ensure!(
        body.expires_unix_secs > body.issued_unix_secs
            && body.expires_unix_secs - body.issued_unix_secs <= MAX_PRESENCE_TTL.as_secs(),
        "invalid V2 Presence lifetime"
    );
    if let Some(now) = now {
        ensure!(
            body.issued_unix_secs <= now.saturating_add(CLOCK_SKEW.as_secs()),
            "V2 Presence issue time is too far in the future"
        );
        ensure!(body.expires_unix_secs > now, "V2 Presence has expired");
    }
    ensure!(
        body.direct_addresses.len() <= MAX_DIRECT_ADDRESSES,
        "too many V2 Presence direct addresses"
    );
    ensure!(
        body.node_addresses.len() <= MAX_NODE_ADDRESSES,
        "too many V2 Presence node addresses"
    );
    ensure!(
        body.prefixes.len() <= MAX_PRESENCE_PREFIXES,
        "too many V2 Presence prefixes"
    );
    ensure!(
        body.links.len() <= MAX_PRESENCE_LINKS,
        "too many V2 Presence links"
    );
    for address in &body.direct_addresses {
        ensure!(
            address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast(),
            "invalid V2 Presence direct address"
        );
    }
    ensure!(
        body.node_addresses
            .iter()
            .all(|address| !body.prefixes.contains(address)),
        "V2 Presence node addresses must not be duplicated as subnet prefixes"
    );
    for prefix in &body.prefixes {
        ensure!(
            prefix.addr() == prefix.network(),
            "non-canonical V2 Presence prefix"
        );
    }
    for address in &body.node_addresses {
        ensure!(
            address.addr() == address.network()
                && address.prefix_len() == if address.addr().is_ipv4() { 32 } else { 128 },
            "V2 Presence node address is not a host prefix"
        );
    }
    for link in &body.links {
        ensure!(link.peer != body.owner, "V2 Presence contains a self-link");
        ensure!(link.cost != 0, "V2 Presence link cost is zero");
        ensure!(
            link.maximum_datagram_size as usize > super::cell::HEADER_LEN,
            "V2 Presence link DATAGRAM ceiling is too small"
        );
    }
    Ok(())
}

fn canonicalize_body(body: &mut PresenceBodyV2) {
    body.direct_addresses.sort_unstable();
    body.node_addresses
        .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr()));
    body.prefixes
        .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
    body.links.sort_by_key(|link| link.peer);
}

fn is_canonical(body: &PresenceBodyV2) -> bool {
    let mut canonical = body.clone();
    canonicalize_body(&mut canonical);
    canonical == *body
        && !has_adjacent_duplicates(&body.direct_addresses)
        && !has_adjacent_duplicates(&body.node_addresses)
        && !has_adjacent_duplicates(&body.prefixes)
        && !body
            .links
            .windows(2)
            .any(|pair| pair[0].peer == pair[1].peer)
}

fn has_adjacent_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values.windows(2).any(|pair| pair[0] == pair[1])
}

fn network_fingerprint(network_id: &str) -> [u8; 32] {
    blake3::derive_key(
        "ironet v2 presence network fingerprint",
        network_id.as_bytes(),
    )
}

fn membership_tag(network_id: &str, unsigned: &[u8], signature: &Signature) -> [u8; 32] {
    let key = blake3::derive_key("ironet v2 presence membership", network_id.as_bytes());
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(unsigned);
    hasher.update(&signature.to_bytes());
    *hasher.finalize().as_bytes()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn unix_secs(now: SystemTime) -> Result<u64> {
    now.duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}

fn host_prefix(address: IpAddr) -> IpNet {
    match address {
        IpAddr::V4(address) => IpNet::V4(Ipv4Net::new(address, 32).expect("valid IPv4 host")),
        IpAddr::V6(address) => IpNet::V6(Ipv6Net::new(address, 128).expect("valid IPv6 host")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(
        key: &SecretKey,
        sequence: u64,
        now: u64,
        prefix: Option<&str>,
        links: Vec<PresenceLinkV2>,
        transit_enabled: bool,
    ) -> PresenceBodyV2 {
        let public = key.public();
        let mut address = [0_u8; 16];
        address[0] = 0xfd;
        address[1..].copy_from_slice(&public.as_bytes()[..15]);
        PresenceBodyV2 {
            owner: public,
            sequence,
            issued_unix_secs: now,
            expires_unix_secs: now + 180,
            direct_addresses: vec!["[2001:db8::1]:443".parse().unwrap()],
            node_addresses: vec![IpNet::from(IpAddr::V6(Ipv6Addr::from(address)))],
            prefixes: prefix
                .into_iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect(),
            links,
            transit_enabled,
        }
    }

    fn signed(
        key: &SecretKey,
        sequence: u64,
        now: u64,
        prefix: Option<&str>,
        links: Vec<PresenceLinkV2>,
        transit_enabled: bool,
    ) -> SignedPresenceV2 {
        SignedPresenceV2::sign(
            body(key, sequence, now, prefix, links, transit_enabled),
            key,
            "network",
        )
        .unwrap()
    }

    #[test]
    fn signed_presence_round_trips_and_binds_owner_network_and_membership() {
        let key = SecretKey::generate();
        let peer = SecretKey::generate();
        let presence = signed(
            &key,
            7,
            1_000,
            Some("11.6.1.0/24"),
            vec![PresenceLinkV2 {
                peer: peer.public(),
                cost: 12,
                healthy: true,
                maximum_datagram_size: 1_382,
            }],
            true,
        );
        let encoded = presence.encode().unwrap();
        let decoded = SignedPresenceV2::decode(encoded).unwrap();
        decoded
            .verify("network", UNIX_EPOCH + Duration::from_secs(1_010))
            .unwrap();
        assert_eq!(decoded, presence);
        assert!(
            decoded
                .verify("other", UNIX_EPOCH + Duration::from_secs(1_010))
                .is_err()
        );

        let mut tampered = decoded.clone();
        tampered.body.sequence += 1;
        assert!(
            tampered
                .verify("network", UNIX_EPOCH + Duration::from_secs(1_010))
                .is_err()
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_duplicates_truncation_and_expiry() {
        let key = SecretKey::generate();
        let mut invalid = body(&key, 1, 1_000, None, Vec::new(), false);
        invalid.direct_addresses.push(invalid.direct_addresses[0]);
        assert!(SignedPresenceV2::sign(invalid, &key, "network").is_err());

        let valid = signed(&key, 1, 1_000, None, Vec::new(), false);
        let mut bytes = valid.encode().unwrap().to_vec();
        bytes.pop();
        assert!(SignedPresenceV2::decode(Bytes::from(bytes)).is_err());
        assert!(
            valid
                .verify("network", UNIX_EPOCH + Duration::from_secs(1_181))
                .is_err()
        );
    }

    #[test]
    fn directory_is_monotonic_and_requires_bilateral_links() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let c = SecretKey::generate();
        let now = UNIX_EPOCH + Duration::from_secs(1_010);
        let mut directory = PresenceDirectoryV2::new("network".into()).unwrap();
        let a_record = signed(
            &a,
            2,
            1_000,
            None,
            vec![PresenceLinkV2 {
                peer: b.public(),
                cost: 10,
                healthy: true,
                maximum_datagram_size: 1_382,
            }],
            false,
        );
        assert_eq!(
            directory.insert(a_record.clone(), now).unwrap(),
            PresenceUpdateV2::Inserted
        );
        assert_eq!(
            directory.insert(a_record.clone(), now).unwrap(),
            PresenceUpdateV2::Duplicate
        );
        assert_eq!(
            directory
                .insert(
                    signed(&a, 3, 1_001, None, a_record.body.links.clone(), false),
                    now,
                )
                .unwrap(),
            PresenceUpdateV2::Renewed
        );
        assert_eq!(
            directory
                .insert(signed(&a, 1, 999, None, Vec::new(), false), now)
                .unwrap(),
            PresenceUpdateV2::Stale
        );
        directory
            .insert(
                signed(
                    &b,
                    1,
                    1_000,
                    None,
                    vec![PresenceLinkV2 {
                        peer: a.public(),
                        cost: 20,
                        healthy: true,
                        maximum_datagram_size: 1_200,
                    }],
                    true,
                ),
                now,
            )
            .unwrap();
        directory
            .insert(
                signed(&c, 1, 1_000, Some("11.6.1.0/24"), Vec::new(), false),
                now,
            )
            .unwrap();
        let topology = directory.compile_topology(1, 1, false, now).unwrap();
        assert!(
            topology
                .snapshot(NodeIdV2(*a.public().as_bytes()))
                .unwrap()
                .lookup_destination("11.6.1.48".parse().unwrap())
                .is_err()
        );
        assert_eq!(
            adjacency_id(a.public(), b.public()),
            adjacency_id(a.public(), b.public())
        );
        assert_ne!(
            adjacency_id(a.public(), b.public()),
            adjacency_id(b.public(), a.public())
        );
    }

    #[test]
    fn expired_presence_revokes_its_prefixes_and_node_addresses() {
        let key = SecretKey::generate();
        let mut directory = PresenceDirectoryV2::new("network".into()).unwrap();
        directory
            .insert(
                signed(&key, 1, 1_000, Some("11.6.1.0/24"), Vec::new(), false),
                UNIX_EPOCH + Duration::from_secs(1_010),
            )
            .unwrap();
        assert_eq!(directory.len(), 1);
        let record = directory.records().next().unwrap();
        assert_eq!(record.body.node_addresses.len(), 1);
        assert_eq!(record.body.node_addresses[0].prefix_len(), 128);
        assert_eq!(record.body.prefixes, ["11.6.1.0/24".parse().unwrap()]);

        assert_eq!(
            directory
                .prune(UNIX_EPOCH + Duration::from_secs(1_181))
                .unwrap(),
            1
        );
        assert!(directory.is_empty());
    }

    #[test]
    fn bilateral_three_node_presence_compiles_a_transit_route_and_exclusions() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let c = SecretKey::generate();
        let now = UNIX_EPOCH + Duration::from_secs(1_010);
        let mut directory = PresenceDirectoryV2::new("network".into()).unwrap();
        for record in [
            signed(
                &a,
                1,
                1_000,
                None,
                vec![PresenceLinkV2 {
                    peer: b.public(),
                    cost: 1,
                    healthy: true,
                    maximum_datagram_size: 1_382,
                }],
                false,
            ),
            signed(
                &b,
                1,
                1_000,
                None,
                vec![
                    PresenceLinkV2 {
                        peer: a.public(),
                        cost: 1,
                        healthy: true,
                        maximum_datagram_size: 1_382,
                    },
                    PresenceLinkV2 {
                        peer: c.public(),
                        cost: 1,
                        healthy: true,
                        maximum_datagram_size: 1_200,
                    },
                ],
                true,
            ),
            signed(
                &c,
                1,
                1_000,
                Some("11.6.1.0/24"),
                vec![PresenceLinkV2 {
                    peer: b.public(),
                    cost: 1,
                    healthy: true,
                    maximum_datagram_size: 1_200,
                }],
                false,
            ),
        ] {
            directory.insert(record, now).unwrap();
        }
        let topology = directory.compile_topology(3, 7, false, now).unwrap();
        let a_snapshot = topology.snapshot(NodeIdV2(*a.public().as_bytes())).unwrap();
        let route = a_snapshot
            .lookup_destination("11.6.1.48".parse().unwrap())
            .unwrap();
        assert_eq!(route.adjacency, adjacency_id(a.public(), b.public()));
        assert_eq!(route.maximum_datagram_size, 1_200);
        assert_eq!(
            a_snapshot.lookup_destination("2001:db8::1".parse().unwrap()),
            Err(super::super::routing::TransitDropReasonV2::UnderlayDestination)
        );

        directory
            .insert(
                signed(
                    &b,
                    2,
                    1_001,
                    None,
                    vec![
                        PresenceLinkV2 {
                            peer: a.public(),
                            cost: 1,
                            healthy: true,
                            maximum_datagram_size: 1_382,
                        },
                        PresenceLinkV2 {
                            peer: c.public(),
                            cost: 1,
                            healthy: true,
                            maximum_datagram_size: 1_200,
                        },
                    ],
                    false,
                ),
                now,
            )
            .unwrap();
        let without_transit = directory.compile_topology(4, 8, false, now).unwrap();
        assert!(
            without_transit
                .snapshot(NodeIdV2(*a.public().as_bytes()))
                .unwrap()
                .lookup_destination("11.6.1.48".parse().unwrap())
                .is_err()
        );
    }
}
