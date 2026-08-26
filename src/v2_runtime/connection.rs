//! V2 endpoint construction, mesh adjacency establishment, and cover-name selection.

use std::{collections::HashSet as StdHashSet, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
    endpoint::{ConnectOptions, Connection, QuicTransportConfig, TlsSessionPartition, presets},
};
use rustc_hash::FxHashMap as HashMap;
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::{
    ALPN, COVER_DNS_SELECTION_TIMEOUT, LIVE_MEDIA_QUIC_BIDI_STREAMS,
    LIVE_MEDIA_QUIC_DATAGRAM_BUFFER, LIVE_MEDIA_QUIC_INITIAL_MTU, LIVE_MEDIA_QUIC_MINIMUM_MTU,
    LIVE_MEDIA_QUIC_RECEIVE_WINDOW, LIVE_MEDIA_QUIC_SEND_WINDOW,
    LIVE_MEDIA_QUIC_STREAM_RECEIVE_WINDOW, LIVE_MEDIA_QUIC_UNI_STREAMS, QUIC_WIRE_VERSION,
    V2PeerConfig, V2RuntimeConfig, autotune::LOW_RTT_CWND_FLOOR_BYTES,
    path_selection::UnderlayPathSelector,
};
use crate::{
    config::validate_cover_sni,
    derp::{
        DerpTransport, identity::load_or_create as load_or_create_derp_identity,
        tls_config as derp_tls_config,
    },
    protocol::v2::{
        presence::adjacency_id,
        routing::{AdjacencyIdV2, RouteAdvertisementV2},
        session::{
            ConnectionRole, NegotiatedSessionV2, SessionPolicyV2, WireLimitsV2, capability,
            negotiate_connection_v2,
        },
    },
};

impl V2RuntimeConfig {
    fn underlay_path_exclusions(&self) -> Vec<IpNet> {
        let mut prefixes = self.excluded_underlay_prefixes.clone();
        prefixes.extend(self.node_addresses.iter().copied());
        prefixes.extend(self.routes.iter().copied());
        prefixes.extend(self.advertised_routes.iter().copied());
        prefixes
            .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
        prefixes.dedup();
        prefixes
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.path_migration.validate()?;
        ensure!(!self.network_id.is_empty(), "V2 network ID is empty");
        ensure!(self.network_id.len() <= 128, "V2 network ID is too long");
        ensure!(
            self.cover_profile_id != 0,
            "V2 cover profile generation zero is reserved"
        );
        ensure!(
            !self.cover_sni_pool.is_empty(),
            "V2 cover SNI pool is empty"
        );
        for name in &self.cover_sni_pool {
            validate_cover_sni(name)?;
        }
        let mut cover_names = self.cover_sni_pool.iter().collect::<Vec<_>>();
        cover_names.sort_unstable();
        let count = cover_names.len();
        cover_names.dedup();
        ensure!(cover_names.len() == count, "duplicate V2 cover SNI");
        ensure!(!self.tun_name.is_empty(), "V2 TUN name is empty");
        ensure!(
            (2..32_766).contains(&self.routing_rule_priority),
            "V2 routing rule priority must be between 2 and 32765"
        );
        ensure!(
            !matches!(self.routing_table, 0 | 253 | 254 | 255),
            "V2 routing table must be a non-reserved Linux routing table"
        );
        let mut families = StdHashSet::new();
        for address in &self.node_addresses {
            ensure!(
                address.prefix_len() == if address.addr().is_ipv4() { 32 } else { 128 },
                "V2 node address {address} must be a host prefix"
            );
            ensure!(
                families.insert(address.addr().is_ipv6()),
                "V2 accepts at most one node address per family"
            );
        }
        RouteAdvertisementV2 {
            generation: 1,
            prefixes: self.advertised_routes.clone(),
        }
        .validate(self.allow_default_routes)?;
        ensure!(
            self.allow_default_routes || self.routes.iter().all(|route| route.prefix_len() != 0),
            "V2 default route was not explicitly enabled"
        );
        let mut peers = self
            .mesh_peers
            .iter()
            .map(|peer| peer.endpoint_id)
            .collect::<Vec<_>>();
        peers.sort_unstable();
        let count = peers.len();
        peers.dedup();
        ensure!(peers.len() == count, "duplicate V2 mesh peer EndpointId");
        let underlay_path_exclusions = self.underlay_path_exclusions();
        for peer in &self.mesh_peers {
            // An invite issuer knows the member identity before that member has
            // an address. Keep that peer as an authenticated accept-only
            // adjacency; the joining node owns the bootstrap locator and dials.
            ensure!(
                peer.addresses.iter().all(|address| address.port() != 0),
                "V2 mesh peer address has port zero"
            );
            ensure!(
                peer.addresses.iter().all(|address| underlay_path_exclusions
                    .iter()
                    .all(|prefix| !prefix.contains(&address.ip()))),
                "V2 mesh peer address is inside an excluded underlay prefix"
            );
        }
        let derp_enabled = !self.derp_servers.is_empty();
        let has_derp_peer = self
            .mesh_peers
            .iter()
            .any(|peer| peer.derp_public_key.is_some());
        ensure!(
            derp_enabled == self.derp_identity_file.is_some(),
            "V2 DERP servers and identity file must be configured together"
        );
        ensure!(
            !has_derp_peer || derp_enabled,
            "V2 DERP peer locator requires configured DERP servers"
        );
        let mut regions = self
            .derp_servers
            .iter()
            .map(|server| server.region_id)
            .collect::<Vec<_>>();
        regions.sort_unstable();
        let region_count = regions.len();
        regions.dedup();
        ensure!(regions.len() == region_count, "duplicate V2 DERP region");
        let mut derp_peers = self
            .mesh_peers
            .iter()
            .filter_map(|peer| peer.derp_public_key)
            .collect::<Vec<_>>();
        derp_peers.sort_unstable();
        let derp_peer_count = derp_peers.len();
        derp_peers.dedup();
        ensure!(
            derp_peers.len() == derp_peer_count,
            "duplicate V2 DERP peer public key"
        );
        Ok(())
    }

    /// Translate the product configuration into the single V2 dataplane
    /// contract. This conversion is intentionally strict: unsupported V1
    /// transport shapes are rejected instead of silently starting a legacy
    /// runtime or weakening a private-link policy.
    pub fn from_product_config(config: &crate::config::Config) -> Result<Self> {
        let mut bind_addresses = config.endpoint_bind_addresses().collect::<Vec<_>>();
        bind_addresses.sort_unstable();
        bind_addresses.dedup();
        ensure!(
            bind_addresses.len() <= 1,
            "V2 requires one dual-stack bind address; found {}",
            bind_addresses.len()
        );
        let bind = bind_addresses
            .into_iter()
            .next()
            .unwrap_or_else(|| "[::]:4000".parse().expect("static V2 bind address"));

        let derp_servers = config.derp_servers()?;
        let mut invite_authorization = HashMap::<EndpointId, bool>::default();
        for (endpoint, revoked) in crate::product::authority_invites(&config.identity_file)
            .unwrap_or_default()
            .into_values()
        {
            invite_authorization
                .entry(endpoint)
                .and_modify(|active| *active |= !revoked)
                .or_insert(!revoked);
        }
        let revoked_invites = invite_authorization
            .into_iter()
            .filter_map(|(endpoint, active)| (!active).then_some(endpoint))
            .collect::<StdHashSet<_>>();
        let mut mesh_peers = Vec::with_capacity(config.peers.len());
        for peer in &config.peers {
            if revoked_invites.contains(&peer.endpoint_id) {
                continue;
            }
            let mut addresses = peer.direct_addresses.clone();
            for link in config
                .links
                .iter()
                .filter(|link| link.peer_id == peer.endpoint_id)
            {
                ensure!(
                    link.exclusive && !link.fallback,
                    "V2 private link {} must remain exclusive without fallback",
                    link.name
                );
                addresses.extend(link.remote_addresses.iter().copied());
            }
            addresses.sort_unstable();
            addresses.dedup();
            mesh_peers.push(V2PeerConfig {
                endpoint_id: peer.endpoint_id,
                addresses,
                derp_public_key: peer.derp_public_key,
            });
        }

        let mut routes = config
            .route_origins
            .iter()
            .flat_map(|origin| origin.prefixes.iter().copied())
            .collect::<Vec<_>>();
        routes.sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
        routes.dedup();

        let result = Self {
            identity_file: config.identity_file.clone(),
            bind,
            excluded_underlay_prefixes: config.excluded_underlay_prefixes.clone(),
            mesh_peers,
            derp_servers,
            derp_identity_file: config
                .relay
                .derp_enabled()
                .then(|| config.derp_identity_file()),
            network_id: config.network_id.clone(),
            cover_sni_pool: config.cover.sni_pool.clone(),
            cover_profile_id: config.cover.profile_id,
            tun_name: config.node_interface.clone(),
            tun_mtu: config.tun_mtu,
            isolate_overlay: config.routing.isolate_overlay,
            routing_table: config.routing.table,
            routing_rule_priority: config.routing.rule_priority,
            node_addresses: config.node_addresses.clone(),
            routes,
            advertised_routes: config.advertised_prefixes.clone(),
            allow_default_routes: config.routing.allow_default_routes,
            subnet_nat: config.routing.nat_enabled,
            transit_enabled: config.routing.transit_enabled,
            autotune: config.autotune.clone(),
            path_migration: config.path_migration.clone(),
            max_egress_bytes_per_second: config.routing.max_egress_bps().map(|bits| bits / 8),
        };
        result.validate()?;
        Ok(result)
    }

    pub(super) async fn build_endpoint(
        &self,
        secret_key: SecretKey,
        derp_transport: Option<Arc<DerpTransport>>,
    ) -> Result<Endpoint> {
        let config = self;
        let mut congestion = noq_proto::congestion::Bbr3Config::default();
        // At <=5 ms, userspace timer wakeups cost more than a complete send
        // quantum and can collapse LAN/Wi-Fi delivery-rate sampling. BBR still
        // enforces cwnd; if live loss proves a shallow policer, its automatic
        // pacing scale immediately disables this bypass for that path lifetime.
        congestion.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        congestion.low_rtt_cwnd_floor(LOW_RTT_CWND_FLOOR_BYTES);
        let transport = QuicTransportConfig::builder()
            // Keep the passive QUIC v1/H3Media surface deterministic across every
            // peer. These are protocol-profile constants, not operator tuning:
            // live bandwidth/RTT/loss adaptation remains inside QUIC BBR3, PMTUD
            // and the bounded V2 admission controller.
            .max_concurrent_bidi_streams(LIVE_MEDIA_QUIC_BIDI_STREAMS.into())
            .max_concurrent_uni_streams(LIVE_MEDIA_QUIC_UNI_STREAMS.into())
            .stream_receive_window(LIVE_MEDIA_QUIC_STREAM_RECEIVE_WINDOW.into())
            .receive_window(LIVE_MEDIA_QUIC_RECEIVE_WINDOW.into())
            .send_window(LIVE_MEDIA_QUIC_SEND_WINDOW)
            .initial_mtu(LIVE_MEDIA_QUIC_INITIAL_MTU)
            .min_mtu(LIVE_MEDIA_QUIC_MINIMUM_MTU)
            .packet_threshold(3)
            .time_threshold(1.125)
            .initial_rtt(Duration::from_millis(333))
            .persistent_congestion_threshold(3)
            .ack_frequency_config(None)
            .allow_spin(false)
            .enable_segmentation_offload(true)
            .keep_alive_interval(Duration::from_secs(1))
            .default_path_keep_alive_interval(Duration::from_millis(
                config.path_migration.keep_alive_ms,
            ))
            .default_path_max_idle_timeout(Duration::from_millis(
                config.path_migration.idle_timeout_ms,
            ))
            // V2 carries a tunnel's long-lived mixed traffic over QUIC DATAGRAMs.
            // Loss-based CUBIC collapses its window on lossy mobile/WAN paths even
            // when receiver feedback proves the path is not queue-congested. BBR3
            // derives pacing and inflight from delivered bandwidth/min-RTT and is
            // therefore the appropriate automatic controller for this dataplane;
            // peers need not expose or coordinate an operator setting.
            // Sub-millisecond host/datacenter paths bypass only the userspace
            // pacing timer after BBR measures min-RTT; its inflight window remains
            // active. WAN paths retain full model-based pacing.
            .congestion_controller_factory(Arc::new(congestion))
            .max_outgoing_bytes_per_second(config.max_egress_bytes_per_second)
            .datagram_send_buffer_size(LIVE_MEDIA_QUIC_DATAGRAM_BUFFER)
            .datagram_receive_buffer_size(Some(LIVE_MEDIA_QUIC_DATAGRAM_BUFFER))
            .send_observed_address_reports(false)
            .receive_observed_address_reports(false)
            .build();
        let mut endpoint_builder = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()])
            .enable_early_data(false)
            .relay_mode(RelayMode::Disabled)
            .transport_config(transport)
            .path_selector(Arc::new(UnderlayPathSelector::new(
                config.underlay_path_exclusions(),
                config.path_migration.clone(),
            )))
            .path_recovery_interval(Duration::from_millis(config.path_migration.keep_alive_ms))
            .path_recovery_probation(Duration::from_millis(
                config.path_migration.recovery_probation_ms,
            ))
            .clear_address_lookup()
            .clear_ip_transports();
        // `clear_ip_transports` removes iroh's default IPv4 + IPv6 pair. Restore
        // both families when the product configuration uses an unspecified bind;
        // a lone `[::]` socket is IPv6-only in the transport and cannot dial an
        // IPv4 invite locator (and conversely for `0.0.0.0`). Both sockets share
        // the configured QUIC port, preserving one externally visible endpoint.
        for bind in endpoint_bind_addresses(config.bind) {
            endpoint_builder = endpoint_builder.bind_addr(bind)?;
        }
        if let Some(transport) = derp_transport {
            endpoint_builder = endpoint_builder.add_custom_transport(transport);
        }
        let endpoint = endpoint_builder
            .bind()
            .await
            .context("binding V2 QUIC endpoint")?;
        Ok(endpoint)
    }
}

pub(super) fn build_v2_derp_transport(
    config: &V2RuntimeConfig,
) -> Result<Option<Arc<DerpTransport>>> {
    if config.derp_servers.is_empty() {
        return Ok(None);
    }
    let identity_file = config
        .derp_identity_file
        .as_deref()
        .context("V2 DERP identity file is missing")?;
    let identity = load_or_create_derp_identity(identity_file)?;
    let public_key = identity.public_key();
    let allowed_peers = config
        .mesh_peers
        .iter()
        .filter_map(|peer| peer.derp_public_key)
        .collect::<StdHashSet<_>>();
    info!(
        %public_key,
        identity_file = %identity_file.display(),
        regions = config.derp_servers.len(),
        peers = allowed_peers.len(),
        "V2 DERP transport configured"
    );
    Ok(Some(DerpTransport::new(
        identity,
        config.derp_servers.clone(),
        allowed_peers,
        derp_tls_config()?,
    )))
}

fn endpoint_bind_addresses(bind: SocketAddr) -> Vec<SocketAddr> {
    match bind.ip() {
        std::net::IpAddr::V4(address) if address.is_unspecified() => vec![
            bind,
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                bind.port(),
            ),
        ],
        std::net::IpAddr::V6(address) if address.is_unspecified() => vec![
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                bind.port(),
            ),
            bind,
        ],
        _ => vec![bind],
    }
}

/// One authenticated logical peer session. Path migration and direct/DERP
/// candidates remain inside this single end-to-end QUIC connection; V2 never
/// creates parallel congestion-control lanes for the same peer.
#[derive(Debug, Clone)]
pub(super) struct PeerSessionV2 {
    pub(super) id: AdjacencyIdV2,
    pub(super) remote_id: EndpointId,
    pub(super) connection: Connection,
    pub(super) negotiated: NegotiatedSessionV2,
}

pub(super) async fn establish_mesh_adjacencies(
    endpoint: &Endpoint,
    config: &V2RuntimeConfig,
    local_id: EndpointId,
    derp_transport: Option<Arc<DerpTransport>>,
) -> Result<Vec<PeerSessionV2>> {
    let expected = config
        .mesh_peers
        .iter()
        .map(|peer| (peer.endpoint_id, peer.clone()))
        .collect::<HashMap<_, _>>();
    let mut dials = JoinSet::new();
    for peer in config
        .mesh_peers
        .iter()
        .filter(|peer| peer.is_dialable())
        .cloned()
    {
        let endpoint = endpoint.clone();
        let network_id = config.network_id.clone();
        let cover_sni_pool = config.cover_sni_pool.clone();
        let derp_transport = derp_transport.clone();
        let cover_profile_id = config.cover_profile_id;
        let policy = session_policy(config, local_id, peer.endpoint_id);
        let fallback_delay =
            (!mesh_should_dial(local_id, peer.endpoint_id)).then_some(Duration::from_millis(750));
        dials.spawn(async move {
            // Normally the lower EndpointId owns the dial. A delayed dial from
            // the other side makes asymmetric product bootstrap robust when
            // only that side has a usable locator. If the primary dial arrives
            // first this task is aborted when the adjacency set completes.
            if let Some(delay) = fallback_delay {
                tokio::time::sleep(delay).await;
            }
            let cover_sni = select_cover_sni_for_peer(
                &cover_sni_pool,
                &network_id,
                local_id,
                peer.endpoint_id,
                cover_profile_id,
                &peer.addresses,
            )
            .await?;
            loop {
                let connection = dial_mesh_peer(
                    &endpoint,
                    &peer,
                    &network_id,
                    &cover_sni,
                    cover_profile_id,
                    derp_transport.as_deref(),
                )
                .await?;
                match negotiate_connection_v2(&connection, &policy).await {
                    Ok(negotiated) => {
                        let remote_id = peer.endpoint_id;
                        return Ok::<_, anyhow::Error>((
                            remote_id,
                            PeerSessionV2 {
                                id: adjacency_id(local_id, remote_id),
                                remote_id,
                                connection,
                                negotiated,
                            },
                        ));
                    }
                    Err(error) => {
                        warn!(
                            peer = %peer.endpoint_id,
                            error = %format_args!("{error:#}"),
                            "retrying V2 mesh candidate after SessionHello failure"
                        );
                        connection.close(1_u8.into(), b"V2 SessionHello failed");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
    }

    let mut adjacencies = HashMap::<EndpointId, PeerSessionV2>::default();
    while adjacencies.len() < expected.len() {
        tokio::select! {
            result = dials.join_next(), if !dials.is_empty() => {
                let Some(joined) = result else {
                    continue;
                };
                let output = match joined {
                    Ok(Ok(output)) => output,
                    Ok(Err(error)) => {
                        warn!(
                            error = %format_args!("{error:#}"),
                            "V2 mesh dial attempt stopped before adjacency establishment"
                        );
                        continue;
                    }
                    Err(error) => {
                        warn!(%error, "V2 mesh dial task panicked before adjacency establishment");
                        continue;
                    }
                };
                let (remote, adjacency) = output;
                if let Some(previous) = adjacencies.insert(remote, adjacency) {
                    previous.connection.close(
                        1_u8.into(),
                        b"duplicate outgoing V2 mesh adjacency",
                    );
                    warn!(peer = %remote, "replacing duplicate outgoing V2 mesh adjacency");
                }
            }
            incoming = endpoint.accept() => {
                let incoming = incoming.context("V2 endpoint closed during mesh establishment")?;
                let accepting = match incoming.accept() {
                    Ok(accepting) => accepting,
                    Err(error) => {
                        // A fallback dial can be rejected by the deterministic
                        // primary dialer while its legitimate connection is
                        // still in flight. Retransmits and abandoned Initials
                        // are likewise connection-local events; none may tear
                        // down the endpoint or the whole dataplane generation.
                        warn!(%error, "ignoring rejected incoming V2 mesh Initial");
                        continue;
                    }
                };
                let connection = match accepting.await {
                    Ok(connection) => connection,
                    Err(error) => {
                        warn!(%error, "ignoring failed incoming V2 mesh handshake");
                        continue;
                    }
                };
                let remote = connection.remote_id();
                let local_primary_dial = expected.get(&remote).is_some_and(|peer| {
                    peer.is_dialable() && mesh_should_dial(local_id, remote)
                });
                if !expected.contains_key(&remote) || local_primary_dial {
                    connection.close(1_u8.into(), b"unexpected V2 mesh dialer");
                    continue;
                }
                let policy = session_policy(config, local_id, remote);
                let negotiated = match negotiate_connection_v2(&connection, &policy).await {
                    Ok(negotiated) => negotiated,
                    Err(error) => {
                        warn!(
                            peer = %remote,
                            error = %format_args!("{error:#}"),
                            "ignoring incoming V2 mesh candidate that failed SessionHello"
                        );
                        connection.close(1_u8.into(), b"V2 SessionHello rejected");
                        continue;
                    }
                };
                let adjacency = PeerSessionV2 {
                    id: adjacency_id(local_id, remote),
                    remote_id: remote,
                    connection,
                    negotiated,
                };
                if let Some(previous) = adjacencies.insert(remote, adjacency) {
                    previous.connection.close(
                        1_u8.into(),
                        b"duplicate incoming V2 mesh adjacency",
                    );
                    warn!(peer = %remote, "replacing duplicate incoming V2 mesh adjacency");
                }
            }
        }
    }
    dials.abort_all();
    let mut adjacencies = adjacencies.into_values().collect::<Vec<_>>();
    adjacencies.sort_by_key(|adjacency| adjacency.remote_id);
    Ok(adjacencies)
}

fn mesh_should_dial(local: EndpointId, remote: EndpointId) -> bool {
    local < remote
}

impl V2PeerConfig {
    fn is_dialable(&self) -> bool {
        !self.addresses.is_empty() || self.derp_public_key.is_some()
    }
}

fn select_cover_sni<'a>(
    pool: &'a [String],
    network_id: &str,
    local: EndpointId,
    remote: EndpointId,
    generation: u32,
) -> Result<&'a str> {
    select_cover_sni_with_preference(
        pool,
        &StdHashSet::new(),
        network_id,
        local,
        remote,
        generation,
    )
}

fn select_cover_sni_with_preference<'a>(
    pool: &'a [String],
    preferred: &StdHashSet<String>,
    network_id: &str,
    local: EndpointId,
    remote: EndpointId,
    generation: u32,
) -> Result<&'a str> {
    ensure!(!pool.is_empty(), "V2 cover SNI pool is empty");
    let mut canonical = pool
        .iter()
        .filter(|name| preferred.is_empty() || preferred.contains(*name))
        .map(String::as_str)
        .collect::<Vec<_>>();
    if canonical.is_empty() {
        canonical.extend(pool.iter().map(String::as_str));
    }
    canonical.sort_unstable();
    let (first, second) = if local < remote {
        (local, remote)
    } else {
        (remote, local)
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v2/live-media-sni\0");
    hasher.update(network_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(first.as_bytes());
    hasher.update(second.as_bytes());
    hasher.update(&generation.to_be_bytes());
    let digest = hasher.finalize();
    let slot =
        u64::from_be_bytes(digest.as_bytes()[..8].try_into().unwrap()) as usize % canonical.len();
    Ok(canonical[slot])
}

async fn select_cover_sni_for_peer(
    pool: &[String],
    network_id: &str,
    local: EndpointId,
    remote: EndpointId,
    generation: u32,
    direct_addresses: &[SocketAddr],
) -> Result<String> {
    let direct_ips = direct_addresses
        .iter()
        .map(SocketAddr::ip)
        .collect::<StdHashSet<_>>();
    if direct_ips.is_empty() {
        return Ok(select_cover_sni(pool, network_id, local, remote, generation)?.to_owned());
    }

    let mut lookups = JoinSet::new();
    for name in pool.iter().cloned() {
        let direct_ips = direct_ips.clone();
        lookups.spawn(async move {
            let Ok(Ok(mut resolved)) = tokio::time::timeout(
                COVER_DNS_SELECTION_TIMEOUT,
                tokio::net::lookup_host((name.as_str(), 0)),
            )
            .await
            else {
                return None;
            };
            let matches = resolved.any(|address| direct_ips.contains(&address.ip()));
            drop(resolved);
            matches.then_some(name)
        });
    }
    let mut preferred = StdHashSet::new();
    while let Some(result) = lookups.join_next().await {
        if let Ok(Some(name)) = result {
            preferred.insert(name);
        }
    }
    Ok(
        select_cover_sni_with_preference(pool, &preferred, network_id, local, remote, generation)?
            .to_owned(),
    )
}

async fn dial_mesh_peer(
    endpoint: &Endpoint,
    peer: &V2PeerConfig,
    network_id: &str,
    cover_sni: &str,
    cover_profile_id: u32,
    derp_transport: Option<&DerpTransport>,
) -> Result<Connection> {
    let mut target = peer.addresses.iter().copied().fold(
        EndpointAddr::new(peer.endpoint_id),
        EndpointAddr::with_ip_addr,
    );
    if let (Some(transport), Some(public_key)) = (derp_transport, peer.derp_public_key) {
        target = target.with_addrs(
            transport
                .remote_addresses(public_key)
                .into_iter()
                .map(TransportAddr::Custom),
        );
    }
    let mut retry_delay = Duration::from_millis(200);
    loop {
        let options = ConnectOptions::new()
            .with_visible_server_name(cover_sni.to_owned())
            .with_tls_session_partition(TlsSessionPartition::new(
                network_id.to_owned(),
                cover_profile_id,
                QUIC_WIRE_VERSION,
            ));
        match endpoint
            .connect_with_opts(target.clone(), ALPN, options)
            .await
        {
            Ok(connecting) => match connecting.await {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    warn!(peer = %peer.endpoint_id, %error, "retrying V2 mesh handshake");
                }
            },
            Err(error) => {
                warn!(peer = %peer.endpoint_id, %error, "retrying V2 mesh dial");
            }
        }
        tokio::time::sleep(retry_delay).await;
        retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(3));
    }
}

pub(super) fn session_policy(
    config: &V2RuntimeConfig,
    local_id: EndpointId,
    remote_id: EndpointId,
) -> SessionPolicyV2 {
    SessionPolicyV2 {
        network_id: config.network_id.clone(),
        local_id,
        remote_id,
        role: ConnectionRole::Data,
        expected_remote_role: Some(ConnectionRole::Data),
        capabilities: capability::KNOWN,
        limits: WireLimitsV2 {
            // This is the Cell codec/session ceiling, not a path-MTU guess.
            // V2Tx intersects it with QUIC's live DATAGRAM maximum for every
            // PacketTrain, so PMTU remains authoritative. Advertising the
            // former 1,382-byte conservative estimate here permanently left
            // usable space in every packet even after QUIC proved a larger
            // path maximum.
            max_datagram_size: u16::MAX,
            max_control_size: 1024 * 1024,
            max_train_size: 64 * 1024,
            max_record_size: u16::MAX as u32,
            max_cells_per_train: 256,
            max_active_trains: 1024,
        },
        cover_profile_id: config.cover_profile_id,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet as StdHashSet, net::SocketAddr};

    use iroh::SecretKey;

    use super::*;
    use crate::config::AutotuneMode;

    fn product_config() -> crate::config::Config {
        toml::from_str(include_str!("../../config/example.toml")).unwrap()
    }

    #[test]
    fn product_configuration_has_one_strict_v2_runtime_translation() {
        let mut config = product_config();
        config.routing.max_egress_mbps = Some(80);
        config.autotune.mode = AutotuneMode::On;
        let runtime = V2RuntimeConfig::from_product_config(&config).unwrap();
        assert_eq!(runtime.bind, "[::]:4000".parse().unwrap());
        assert_eq!(runtime.tun_name, config.node_interface);
        assert_eq!(runtime.isolate_overlay, config.routing.isolate_overlay);
        assert_eq!(runtime.routing_table, config.routing.table);
        assert_eq!(runtime.routing_rule_priority, config.routing.rule_priority);
        assert_eq!(runtime.node_addresses, config.node_addresses);
        assert_eq!(runtime.advertised_routes, config.advertised_prefixes);
        assert_eq!(
            runtime.excluded_underlay_prefixes,
            config.excluded_underlay_prefixes
        );
        let path_exclusions = runtime.underlay_path_exclusions();
        assert!(
            config
                .node_addresses
                .iter()
                .chain(&config.advertised_prefixes)
                .all(|prefix| path_exclusions.contains(prefix))
        );
        assert_eq!(runtime.cover_sni_pool, ["media.example"]);
        assert!(runtime.mesh_peers.is_empty());
        assert_eq!(runtime.autotune.mode, AutotuneMode::On);
        assert_eq!(runtime.path_migration, config.path_migration);
        assert_eq!(runtime.max_egress_bytes_per_second, Some(10_000_000));
    }

    #[test]
    fn runtime_session_policy_advertises_the_cell_codec_ceiling() {
        let runtime = V2RuntimeConfig::from_product_config(&product_config()).unwrap();
        let local = SecretKey::from_bytes(&[1; 32]).public();
        let remote = SecretKey::from_bytes(&[2; 32]).public();
        let policy = session_policy(&runtime, local, remote);

        assert_eq!(policy.limits.max_datagram_size, u16::MAX);
        assert_eq!(policy.limits.max_train_size, 64 * 1024);
        policy.limits.validate().unwrap();
    }

    #[test]
    fn unspecified_product_bind_expands_to_a_dual_stack_socket_pair() {
        assert_eq!(
            endpoint_bind_addresses("[::]:4000".parse().unwrap()),
            [
                "0.0.0.0:4000".parse().unwrap(),
                "[::]:4000".parse().unwrap(),
            ]
        );
        assert_eq!(
            endpoint_bind_addresses("0.0.0.0:4001".parse().unwrap()),
            [
                "0.0.0.0:4001".parse().unwrap(),
                "[::]:4001".parse().unwrap(),
            ]
        );
        assert_eq!(
            endpoint_bind_addresses("192.0.2.7:4002".parse().unwrap()),
            ["192.0.2.7:4002".parse().unwrap()]
        );
    }

    #[test]
    fn product_translation_rejects_multiple_bind_addresses() {
        let mut config = product_config();
        config.bind_addresses = vec![
            "0.0.0.0:4000".parse().unwrap(),
            "[::]:4000".parse().unwrap(),
        ];
        let error = V2RuntimeConfig::from_product_config(&config)
            .unwrap_err()
            .to_string();
        assert!(error.contains("one dual-stack bind address"));
    }

    #[test]
    fn product_translation_accepts_invited_accept_only_peer() {
        let mut config = product_config();
        config.peers.push(crate::config::PeerConfig {
            name: "invited-peer".into(),
            endpoint_id: SecretKey::from_bytes(&[9; 32]).public(),
            direct_addresses: Vec::new(),
            derp_public_key: None,
        });
        let runtime = V2RuntimeConfig::from_product_config(&config).unwrap();
        assert_eq!(runtime.mesh_peers.len(), 1);
        assert!(!runtime.mesh_peers[0].is_dialable());
    }

    #[test]
    fn live_media_sni_pool_selection_is_stable_symmetric_and_order_independent() {
        let one = SecretKey::from_bytes(&[1; 32]).public();
        let two = SecretKey::from_bytes(&[2; 32]).public();
        let pool = vec![
            "video-c.example".to_owned(),
            "video-a.example".to_owned(),
            "video-b.example".to_owned(),
        ];
        let selected = select_cover_sni(&pool, "network-a", one, two, 7).unwrap();
        assert!(pool.iter().any(|candidate| candidate == selected));
        assert_eq!(
            selected,
            select_cover_sni(&pool, "network-a", two, one, 7).unwrap()
        );
        let mut reversed = pool.clone();
        reversed.reverse();
        assert_eq!(
            selected,
            select_cover_sni(&reversed, "network-a", one, two, 7).unwrap()
        );
        assert!(validate_cover_sni("live-edge.example").is_ok());
        assert!(validate_cover_sni("-invalid.example").is_err());
        assert!(validate_cover_sni("invalid..example").is_err());
    }

    #[test]
    fn live_media_sni_prefers_names_matching_peer_direct_addresses() {
        let one = SecretKey::from_bytes(&[1; 32]).public();
        let two = SecretKey::from_bytes(&[2; 32]).public();
        let pool = vec![
            "video-c.example".to_owned(),
            "video-a.example".to_owned(),
            "video-b.example".to_owned(),
        ];
        let preferred =
            StdHashSet::from(["video-a.example".to_owned(), "video-b.example".to_owned()]);
        let selected =
            select_cover_sni_with_preference(&pool, &preferred, "network-a", one, two, 7).unwrap();
        assert!(preferred.contains(selected));
        assert_eq!(
            selected,
            select_cover_sni_with_preference(&pool, &preferred, "network-a", two, one, 7,).unwrap()
        );

        let unmatched = StdHashSet::from(["not-in-pool.example".to_owned()]);
        assert_eq!(
            select_cover_sni_with_preference(&pool, &unmatched, "network-a", one, two, 7,).unwrap(),
            select_cover_sni(&pool, "network-a", one, two, 7).unwrap()
        );
    }

    #[tokio::test]
    async fn live_media_sni_dns_ranking_is_bounded_and_uses_direct_ip() {
        let one = SecretKey::from_bytes(&[1; 32]).public();
        let two = SecretKey::from_bytes(&[2; 32]).public();
        let selected = select_cover_sni_for_peer(
            &["not-a-real-name.invalid".to_owned(), "localhost".to_owned()],
            "network-a",
            one,
            two,
            7,
            &[SocketAddr::from(([127, 0, 0, 1], 443))],
        )
        .await
        .unwrap();
        assert_eq!(selected, "localhost");
    }
}
