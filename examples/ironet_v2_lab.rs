use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use ipnet::IpNet;
use iroh::EndpointId;
use ironet::{
    derp::{DerpPublicKey, DerpServer},
    v2_runtime::{V2PeerConfig, V2RuntimeConfig, run},
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "ironet-v2-lab",
    about = "Clean-slate Ironet V2 blue-green dataplane"
)]
struct Args {
    #[arg(long, default_value = "/var/lib/ironet-v2/identity.key")]
    identity_file: PathBuf,
    #[arg(long, default_value = "[::]:443")]
    bind: SocketAddr,
    /// Compatibility alias for one mesh peer. New scripts should use
    /// --mesh-peer and --mesh-peer-derp directly.
    #[arg(long)]
    peer: Option<EndpointId>,
    #[arg(long = "peer-address")]
    peer_addresses: Vec<SocketAddr>,
    /// Compatibility alias for the DERP locator of --peer.
    #[arg(long = "peer-derp-key")]
    peer_derp_public_key: Option<DerpPublicKey>,
    /// Add an authenticated direct mesh adjacency as ENDPOINT_ID@SOCKET_ADDR.
    /// Repeat the option to configure more than one peer.
    #[arg(long = "mesh-peer", value_name = "ENDPOINT_ID@SOCKET_ADDR")]
    mesh_peers: Vec<MeshPeerArg>,
    /// Add a DERP locator as ENDPOINT_ID@DERP_PUBLIC_KEY. It can be combined
    /// with direct --mesh-peer locators for automatic QUIC path migration.
    #[arg(long = "mesh-peer-derp", value_name = "ENDPOINT_ID@DERP_PUBLIC_KEY")]
    mesh_peer_derp: Vec<MeshPeerDerpArg>,
    /// Tailscale DERP server URL. Repeat for multiple independent regions.
    #[arg(long = "derp-server", value_name = "URL")]
    derp_servers: Vec<String>,
    #[arg(long = "derp-identity-file")]
    derp_identity_file: Option<PathBuf>,
    #[arg(long, default_value = "ironet-v2")]
    network_id: String,
    /// Add a name to the network-level LiveMedia SNI pool. Selection is
    /// automatic and stable per peer/profile generation.
    #[arg(long = "cover-sni", default_value = "media.example")]
    cover_sni_pool: Vec<String>,
    #[arg(long, default_value_t = 1)]
    cover_profile_id: u32,
    #[arg(long, default_value = "ironet-v2")]
    tun_name: String,
    #[arg(long, default_value_t = 1500)]
    tun_mtu: u16,
    /// Additional IPv4/IPv6 prefix routed through the V2 peer.
    #[arg(long = "route")]
    routes: Vec<IpNet>,
    /// IPv4/IPv6 prefix reachable behind this node. It is announced only
    /// after authenticated SessionHello completion.
    #[arg(long = "advertise-route")]
    advertised_routes: Vec<IpNet>,
    /// Permit an explicitly advertised or manually installed /0 route.
    #[arg(long)]
    allow_default_routes: bool,
    /// Disable the default MASQUERADE/NAT66 behavior for advertised routes.
    #[arg(long = "no-subnet-nat", action = clap::ArgAction::SetFalse, default_value_t = true)]
    subnet_nat: bool,
    /// Permit this node to appear as an intermediate hop in V2 Presence
    /// topology compilation.
    #[arg(long)]
    transit: bool,
}

#[derive(Debug, Clone)]
struct MeshPeerArg {
    endpoint_id: EndpointId,
    address: SocketAddr,
}

#[derive(Debug, Clone)]
struct MeshPeerDerpArg {
    endpoint_id: EndpointId,
    public_key: DerpPublicKey,
}

impl FromStr for MeshPeerArg {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (endpoint_id, address) = value
            .split_once('@')
            .context("mesh peer must be ENDPOINT_ID@SOCKET_ADDR")?;
        ensure!(
            !endpoint_id.is_empty() && !address.is_empty(),
            "empty mesh peer field"
        );
        Ok(Self {
            endpoint_id: endpoint_id
                .parse()
                .context("invalid mesh peer EndpointId")?,
            address: address
                .parse()
                .context("invalid mesh peer socket address")?,
        })
    }
}

impl FromStr for MeshPeerDerpArg {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (endpoint_id, public_key) = value
            .split_once('@')
            .context("mesh DERP peer must be ENDPOINT_ID@DERP_PUBLIC_KEY")?;
        ensure!(
            !endpoint_id.is_empty() && !public_key.is_empty(),
            "empty mesh DERP peer field"
        );
        Ok(Self {
            endpoint_id: endpoint_id
                .parse()
                .context("invalid mesh DERP peer EndpointId")?,
            public_key: public_key.parse().context("invalid mesh DERP public key")?,
        })
    }
}

fn merge_mesh_peer(
    peers: &mut Vec<V2PeerConfig>,
    endpoint_id: EndpointId,
    addresses: impl IntoIterator<Item = SocketAddr>,
    derp_public_key: Option<DerpPublicKey>,
) -> Result<()> {
    let peer = match peers
        .iter_mut()
        .find(|existing| existing.endpoint_id == endpoint_id)
    {
        Some(existing) => existing,
        None => {
            peers.push(V2PeerConfig {
                endpoint_id,
                addresses: Vec::new(),
                derp_public_key: None,
            });
            peers.last_mut().expect("peer was just appended")
        }
    };
    peer.addresses.extend(addresses);
    peer.addresses.sort_unstable();
    peer.addresses.dedup();
    if let Some(key) = derp_public_key {
        ensure!(
            peer.derp_public_key.is_none_or(|current| current == key),
            "conflicting DERP keys for mesh peer {endpoint_id}"
        );
        peer.derp_public_key = Some(key);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_target(false)
        .init();
    let args = Args::parse();
    let mut mesh_peers = Vec::<V2PeerConfig>::new();
    for peer in args.mesh_peers {
        merge_mesh_peer(&mut mesh_peers, peer.endpoint_id, [peer.address], None)?;
    }
    for peer in args.mesh_peer_derp {
        merge_mesh_peer(
            &mut mesh_peers,
            peer.endpoint_id,
            std::iter::empty(),
            Some(peer.public_key),
        )?;
    }
    if let Some(peer) = args.peer {
        merge_mesh_peer(
            &mut mesh_peers,
            peer,
            args.peer_addresses,
            args.peer_derp_public_key,
        )?;
    } else {
        ensure!(
            args.peer_addresses.is_empty() && args.peer_derp_public_key.is_none(),
            "--peer-address and --peer-derp-key require --peer"
        );
    }
    let derp_servers = args
        .derp_servers
        .iter()
        .map(|value| DerpServer::parse(value))
        .collect::<Result<Vec<_>>>()?;
    run(V2RuntimeConfig {
        identity_file: args.identity_file,
        bind: args.bind,
        excluded_underlay_prefixes: Vec::new(),
        mesh_peers,
        derp_servers,
        derp_identity_file: args.derp_identity_file,
        network_id: args.network_id,
        cover_sni_pool: args.cover_sni_pool,
        cover_profile_id: args.cover_profile_id,
        tun_name: args.tun_name,
        tun_mtu: args.tun_mtu,
        isolate_overlay: true,
        routing_table: 211,
        routing_rule_priority: 10_000,
        node_addresses: Vec::new(),
        routes: args.routes,
        advertised_routes: args.advertised_routes,
        allow_default_routes: args.allow_default_routes,
        subnet_nat: args.subnet_nat,
        transit_enabled: args.transit,
        autotune: Default::default(),
        path_migration: Default::default(),
        max_egress_bytes_per_second: None,
    })
    .await
}
