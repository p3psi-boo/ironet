use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub length: usize,
    /// Protocol-semantic packets that must retain latency service regardless
    /// of flow age/rate: ICMP, TCP handshake/teardown, and payload-free ACKs.
    pub latency_protected: bool,
}

/// Directional network flow identity used by the V2 dataplane.  Ports are
/// absent for protocols without a TCP/UDP-style header and for fragmented IP
/// datagrams. Using the same address/protocol key for every fragment prevents
/// the first and later fragments from selecting different route leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

impl From<PacketInfo> for FlowKey {
    fn from(packet: PacketInfo) -> Self {
        Self {
            source: packet.source,
            destination: packet.destination,
            protocol: packet.protocol,
            source_port: packet.source_port,
            destination_port: packet.destination_port,
        }
    }
}

#[cfg(test)]
fn validate_ip_packet(packet: &[u8]) -> Result<()> {
    inspect_ip_packet(packet).map(|_| ())
}

pub fn inspect_ip_packet(packet: &[u8]) -> Result<PacketInfo> {
    ensure!(!packet.is_empty(), "empty packet");
    match packet[0] >> 4 {
        4 => validate_ipv4(packet),
        6 => validate_ipv6(packet),
        version => bail!("unsupported IP version {version}"),
    }
}

/// Return the IP TTL/Hop-Limit after validating the packet. V2 copies this
/// value into its fixed routing shim so overlay transit can enforce logical IP
/// hop semantics without opening PacketTrain records.
pub fn ip_hop_limit(packet: &[u8]) -> Result<u8> {
    inspect_ip_packet(packet)?;
    Ok(ip_hop_limit_validated(packet))
}

pub(crate) fn ip_hop_limit_validated(packet: &[u8]) -> u8 {
    match packet[0] >> 4 {
        4 => packet[8],
        6 => packet[7],
        _ => unreachable!("packet version was validated"),
    }
}

/// Return `(ICMP type, echo sequence)` for a validated-looking IPv4 echo
/// packet. This is used only by the opt-in latency probe trace target and is
/// intentionally allocation-free on the dataplane path.
pub(crate) fn icmpv4_echo_probe(packet: &[u8]) -> Option<(u8, u16)> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 1 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    let kind = packet[header_len];
    if !matches!(kind, 0 | 8) {
        return None;
    }
    Some((
        kind,
        u16::from_be_bytes([packet[header_len + 6], packet[header_len + 7]]),
    ))
}

/// Decrement the network hop limit before forwarding a packet entirely in
/// userspace. This preserves the loop bound that the kernel would normally
/// apply between two different interfaces.
pub fn decrement_hop_limit(packet: &mut [u8]) -> Result<()> {
    inspect_ip_packet(packet)?;
    decrement_hop_limit_validated(packet)
}

/// Decrement the hop limit after [`inspect_ip_packet`] has already validated
/// this exact packet. Transit forwarding carries that parsed metadata beside
/// the owned buffer, avoiding two additional full header walks per packet.
pub(crate) fn decrement_hop_limit_validated(packet: &mut [u8]) -> Result<()> {
    match packet[0] >> 4 {
        4 => {
            ensure!(packet[8] > 1, "IPv4 TTL expired");
            packet[8] -= 1;
            // TTL and protocol form one 16-bit word. Decrementing the TTL by
            // one adds 0x0100 to the one's-complement header checksum.
            let checksum = u32::from(u16::from_be_bytes([packet[10], packet[11]]));
            let updated = checksum + 0x0100;
            let folded = ((updated & 0xffff) + (updated >> 16)) as u16;
            packet[10..12].copy_from_slice(&folded.to_be_bytes());
        }
        6 => {
            ensure!(packet[7] > 1, "IPv6 hop limit expired");
            packet[7] -= 1;
        }
        _ => unreachable!("packet version was validated"),
    }
    Ok(())
}

fn validate_ipv4(packet: &[u8]) -> Result<PacketInfo> {
    ensure!(packet.len() >= 20, "truncated IPv4 header");
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    ensure!(header_len >= 20, "invalid IPv4 header length");
    ensure!(packet.len() >= header_len, "truncated IPv4 options");
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    ensure!(total_len >= header_len, "invalid IPv4 total length");
    ensure!(packet.len() == total_len, "IPv4 packet length mismatch");
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let protocol = packet[9];
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let fragment_offset = fragment & 0x1fff;
    let more_fragments = fragment & 0x2000 != 0;
    let (source_port, destination_port) = if fragment_offset == 0 && !more_fragments {
        transport_ports(packet, header_len, protocol)
    } else {
        (None, None)
    };
    let latency_protected = latency_protected_transport(
        packet,
        header_len,
        protocol,
        fragment_offset == 0 && !more_fragments,
    );
    Ok(PacketInfo {
        source: source.into(),
        destination: destination.into(),
        protocol,
        source_port,
        destination_port,
        length: total_len,
        latency_protected,
    })
}

fn validate_ipv6(packet: &[u8]) -> Result<PacketInfo> {
    ensure!(packet.len() >= 40, "truncated IPv6 header");
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    ensure!(payload_len != 0, "IPv6 jumbograms are not supported");
    let total_len = 40 + payload_len;
    ensure!(packet.len() == total_len, "IPv6 packet length mismatch");
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
    let (protocol, transport_offset, unfragmented) = ipv6_transport_header(packet)?;
    let (source_port, destination_port) = if unfragmented {
        transport_ports(packet, transport_offset, protocol)
    } else {
        (None, None)
    };
    let latency_protected =
        latency_protected_transport(packet, transport_offset, protocol, unfragmented);
    Ok(PacketInfo {
        source: source.into(),
        destination: destination.into(),
        protocol,
        source_port,
        destination_port,
        length: total_len,
        latency_protected,
    })
}

fn latency_protected_transport(
    packet: &[u8],
    transport_offset: usize,
    protocol: u8,
    unfragmented: bool,
) -> bool {
    if matches!(protocol, 1 | 58) {
        return true;
    }
    if protocol != 6 || !unfragmented || packet.len() < transport_offset.saturating_add(20) {
        return false;
    }
    let flags = packet[transport_offset + 13];
    if flags & (0x01 | 0x02 | 0x04) != 0 {
        return true;
    }
    let header_len = usize::from(packet[transport_offset + 12] >> 4) * 4;
    header_len >= 20 && transport_offset.saturating_add(header_len) == packet.len()
}

fn transport_ports(packet: &[u8], offset: usize, protocol: u8) -> (Option<u16>, Option<u16>) {
    if !matches!(protocol, 6 | 17) || packet.len() < offset.saturating_add(4) {
        return (None, None);
    }
    (
        Some(u16::from_be_bytes([packet[offset], packet[offset + 1]])),
        Some(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]])),
    )
}

/// Locate the upper-layer header while bounding extension-header traversal.
/// ESP and unknown extension types intentionally terminate parsing: the
/// V2 dataplane can still group them by addresses and protocol without looking
/// through encrypted or unsupported headers.
fn ipv6_transport_header(packet: &[u8]) -> Result<(u8, usize, bool)> {
    let mut next = packet[6];
    let mut offset = 40_usize;
    let mut unfragmented = true;

    for _ in 0..8 {
        match next {
            // Hop-by-hop options, routing, and destination options share the
            // same 8-octet-unit length encoding.
            0 | 43 | 60 => {
                ensure!(
                    packet.len() >= offset + 2,
                    "truncated IPv6 extension header"
                );
                next = packet[offset];
                let length = (usize::from(packet[offset + 1]) + 1) * 8;
                ensure!(
                    packet.len() >= offset + length,
                    "truncated IPv6 extension header"
                );
                offset += length;
            }
            // An atomic fragment (offset zero, M=0) is safe to inspect. For a
            // genuinely fragmented datagram suppress ports on every fragment
            // so all of them share one V2 dataplane key and route lease.
            44 => {
                ensure!(packet.len() >= offset + 8, "truncated IPv6 fragment header");
                next = packet[offset];
                let fragment = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                unfragmented = fragment & 0xfff9 == 0;
                offset += 8;
            }
            // Authentication Header length is expressed in 32-bit words,
            // excluding its first two words.
            51 => {
                ensure!(packet.len() >= offset + 2, "truncated IPv6 AH header");
                next = packet[offset];
                let length = (usize::from(packet[offset + 1]) + 2) * 4;
                ensure!(packet.len() >= offset + length, "truncated IPv6 AH header");
                offset += length;
            }
            _ => return Ok((next, offset, unfragmented)),
        }
    }
    bail!("too many IPv6 extension headers")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_minimal_ipv4_packet() {
        let mut packet = [0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[8] = 37;
        validate_ip_packet(&packet).unwrap();
        assert_eq!(ip_hop_limit(&packet).unwrap(), 37);
    }

    #[test]
    fn extracts_directional_tcp_flow_key() {
        let mut packet = [0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&42_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&22_u16.to_be_bytes());

        let info = inspect_ip_packet(&packet).unwrap();
        assert_eq!(info.protocol, 6);
        assert_eq!(info.source_port, Some(42_000));
        assert_eq!(info.destination_port, Some(22));
        assert_eq!(
            FlowKey::from(info).source,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn tcp_control_and_payload_free_ack_are_latency_protected_by_semantics() {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[9] = 6;
        packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x10;
        assert!(inspect_ip_packet(&packet).unwrap().latency_protected);

        packet.push(1);
        packet[2..4].copy_from_slice(&41_u16.to_be_bytes());
        assert!(!inspect_ip_packet(&packet).unwrap().latency_protected);

        packet[33] = 0x02;
        assert!(inspect_ip_packet(&packet).unwrap().latency_protected);
    }

    #[test]
    fn packet_size_does_not_make_tcp_data_latency_protected() {
        let mut packet = vec![0_u8; 32 * 1024];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = 6;
        packet[32] = 5 << 4;
        packet[33] = 0x18;
        let info = inspect_ip_packet(&packet).unwrap();
        assert!(!info.latency_protected);
        assert_eq!(info.length, packet.len());
    }

    #[test]
    fn icmp_is_always_latency_protected() {
        let mut packet = [0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[9] = 1;
        assert!(inspect_ip_packet(&packet).unwrap().latency_protected);
    }

    #[test]
    fn extracts_ports_after_ipv6_extension_header() {
        let mut packet = [0_u8; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16_u16.to_be_bytes());
        packet[6] = 60;
        packet[40] = 17;
        packet[41] = 0;
        packet[48..50].copy_from_slice(&53_u16.to_be_bytes());
        packet[50..52].copy_from_slice(&5_353_u16.to_be_bytes());

        let info = inspect_ip_packet(&packet).unwrap();
        assert_eq!(info.protocol, 17);
        assert_eq!(info.source_port, Some(53));
        assert_eq!(info.destination_port, Some(5_353));
    }

    #[test]
    fn every_ipv4_fragment_uses_the_same_portless_flow_key() {
        let mut first = [0_u8; 40];
        first[0] = 0x45;
        first[2..4].copy_from_slice(&40_u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        first[9] = 6;
        first[12..16].copy_from_slice(&[10, 0, 0, 1]);
        first[16..20].copy_from_slice(&[10, 0, 0, 2]);
        first[20..22].copy_from_slice(&42_000_u16.to_be_bytes());
        first[22..24].copy_from_slice(&22_u16.to_be_bytes());
        let mut later = first;
        later[6..8].copy_from_slice(&1_u16.to_be_bytes());

        let first = FlowKey::from(inspect_ip_packet(&first).unwrap());
        let later = FlowKey::from(inspect_ip_packet(&later).unwrap());
        assert_eq!(first, later);
        assert_eq!(first.source_port, None);
        assert_eq!(first.destination_port, None);
    }

    #[test]
    fn rejects_truncated_ipv6_packet() {
        let mut packet = [0_u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        assert!(validate_ip_packet(&packet).is_err());
    }

    #[test]
    fn rejects_trailing_ipv4_bytes() {
        let mut packet = [0_u8; 21];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        assert!(validate_ip_packet(&packet).is_err());
    }

    #[test]
    fn forwarding_decrements_ipv4_ttl_and_updates_checksum() {
        let mut packet = [0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[10..12].copy_from_slice(&0x1234_u16.to_be_bytes());
        decrement_hop_limit(&mut packet).unwrap();
        assert_eq!(packet[8], 63);
        assert_eq!(u16::from_be_bytes([packet[10], packet[11]]), 0x1334);
    }

    #[test]
    fn forwarding_rejects_expired_ipv6_hop_limit() {
        let mut packet = [0_u8; 40];
        packet[0] = 0x60;
        packet[7] = 1;
        assert!(decrement_hop_limit(&mut packet).is_err());
    }
}
