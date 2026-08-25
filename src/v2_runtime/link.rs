use std::net::SocketAddr;

use iroh::endpoint::{Connection, LocalTransportAddr};

pub(super) fn ticket_partition_label(
    network_id: &str,
    cover_profile: u32,
    quic_version: u32,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v2/ticket-partition\0");
    hasher.update(network_id.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{}:{cover_profile}:{quic_version}",
        hex::encode(&digest.as_bytes()[..8])
    )
}

pub(super) fn selected_direct_addresses(connection: &Connection, port: u16) -> Vec<SocketAddr> {
    if port == 0 {
        return Vec::new();
    }
    connection
        .paths()
        .iter()
        .filter(|path| path.is_selected())
        .filter_map(|path| match path.local_addr() {
            LocalTransportAddr::Ip(Some(address))
                if !address.is_unspecified() && !address.is_multicast() =>
            {
                Some(SocketAddr::new(*address, port))
            }
            _ => None,
        })
        .collect()
}

pub(super) fn selected_path_cost(connection: &Connection) -> u32 {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map(|path| path.rtt().as_micros().clamp(1, u128::from(u32::MAX)) as u32)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_partition_is_stable_and_hides_network_name() {
        let first = ticket_partition_label("private-network-name", 7, 1);
        assert_eq!(first, ticket_partition_label("private-network-name", 7, 1));
        assert_ne!(first, ticket_partition_label("other-network", 7, 1));
        assert_ne!(first, ticket_partition_label("private-network-name", 8, 1));
        assert!(!first.contains("private-network-name"));
        assert!(first.ends_with(":7:1"));
    }
}
