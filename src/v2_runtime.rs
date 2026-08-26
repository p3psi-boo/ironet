//! Ironet V2 production runtime.
//!
//! V2 is the only daemon dataplane. It intentionally has no legacy decoder,
//! negotiation fallback, or shared mutable state with the removed protocol.

mod autotune;
mod connection;
mod dataplane;
mod host_network;
mod link;
mod mesh;
mod path_selection;
mod route_selection;
mod status_projection;
mod telemetry;

use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    process::Command,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use iroh::{EndpointId, endpoint::Connection};
use rustc_hash::FxHashMap as HashMap;
use tokio::sync::{broadcast, oneshot, watch};
use tracing::{info, warn};

pub(crate) use crate::config::validate_cover_sni;
use connection::build_v2_derp_transport;
pub(crate) use host_network::cleanup_v2_nat_all;
pub use host_network::{derived_overlay_address, derived_overlay_ipv4_address};
use mesh::run_mesh;
use telemetry::RuntimeMetrics;

use crate::{
    config::{AutotuneConfig, PathMigrationConfig},
    derp::{DerpPublicKey, DerpServer},
    identity,
    protocol::v2::policy::runtime::{PolicyEngine, PolicyLoader},
    trace::OverlayTraceOamEvent,
};

const ALPN: &[u8] = b"h3";
const COVER_PROFILE_NAME: &str = "LiveMedia";
const QUIC_WIRE_VERSION: u32 = 1;
/// Shared ordinary-ingress merge budget used by TUN setup and host fq_codel
/// sizing. It is a global byte bound before route dispatch; each adjacency
/// still admits at most 512 KiB into its latency-sensitive scheduler, so this
/// merge boundary does not deepen the paced path queue.
pub(super) const TUN_REGULAR_INPUT_BYTES: usize = 512 * 1024;
const LIVE_MEDIA_QUIC_MINIMUM_MTU: u16 = 1_200;
const LIVE_MEDIA_QUIC_INITIAL_MTU: u16 = 1_200;
const LIVE_MEDIA_QUIC_BIDI_STREAMS: u32 = 100;
const LIVE_MEDIA_QUIC_UNI_STREAMS: u32 = 16;
const LIVE_MEDIA_QUIC_STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;
const LIVE_MEDIA_QUIC_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const LIVE_MEDIA_QUIC_SEND_WINDOW: u64 = 16 * 1024 * 1024;
const LIVE_MEDIA_QUIC_DATAGRAM_BUFFER: usize = 32 * 1024 * 1024;
const COVER_DNS_SELECTION_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct V2PeerConfig {
    pub endpoint_id: EndpointId,
    pub addresses: Vec<SocketAddr>,
    pub derp_public_key: Option<DerpPublicKey>,
}

#[derive(Debug, Clone)]
pub struct V2RuntimeConfig {
    pub identity_file: PathBuf,
    pub bind: SocketAddr,
    /// IP prefixes that neither side of an automatically discovered direct
    /// underlay path may use. This is enforced by the live path selector, not
    /// only when configured locators are parsed.
    pub excluded_underlay_prefixes: Vec<IpNet>,
    /// Static authenticated adjacencies for the V2 mesh runtime. Repeating an
    /// EndpointId merges its locators. Dial ownership is derived from the two
    /// EndpointIds so only one side initiates each direct QUIC adjacency.
    pub mesh_peers: Vec<V2PeerConfig>,
    pub derp_servers: Vec<DerpServer>,
    pub derp_identity_file: Option<PathBuf>,
    pub network_id: String,
    /// Network-level LiveMedia SNI pool. The dialer chooses one stable entry
    /// per peer and cover-profile generation; pool order is irrelevant.
    pub cover_sni_pool: Vec<String>,
    pub cover_profile_id: u32,
    pub tun_name: String,
    pub tun_mtu: u16,
    /// Keep every overlay destination in a dedicated policy-routing table.
    /// Disabling this deliberately installs only protocol-tagged routes in
    /// `main`; it is never inferred from the route inventory.
    pub isolate_overlay: bool,
    pub routing_table: u32,
    pub routing_rule_priority: u32,
    /// Stable local overlay host addresses. Product configurations provide
    /// these explicitly; the standalone lab harness derives them.
    pub node_addresses: Vec<IpNet>,
    pub routes: Vec<IpNet>,
    pub advertised_routes: Vec<IpNet>,
    pub allow_default_routes: bool,
    pub subnet_nat: bool,
    pub transit_enabled: bool,
    pub autotune: AutotuneConfig,
    pub path_migration: PathMigrationConfig,
    pub max_egress_bytes_per_second: Option<u64>,
}

#[derive(Debug)]
pub struct V2RuntimeState {
    endpoint_id: EndpointId,
    started_unix: u64,
    started_at: Instant,
    interface: String,
    tun_mtu: u16,
    peers: RwLock<HashMap<EndpointId, crate::status::PeerStatus>>,
    connections: RwLock<HashMap<EndpointId, Connection>>,
    metrics: RwLock<HashMap<EndpointId, Arc<RuntimeMetrics>>>,
    tun_ingress_metrics: Arc<RuntimeMetrics>,
    mesh: RwLock<crate::status::MeshStatus>,
    gateway: crate::status::GatewayStatus,
    routes: RwLock<Vec<crate::status::RouteStatus>>,
    routes_ready: AtomicBool,
    pub(super) cpu_utilization_per_mille: AtomicU64,
    pub(super) autotune_state_dir: PathBuf,
    pub(super) autotune: AutotuneConfig,
    pub(super) policy_loader: std::sync::OnceLock<Option<PolicyLoader>>,
    pub(super) max_egress_bytes_per_second: Option<u64>,
    /// Node egress coordinator (plan section 9); pass-through when no
    /// `routing.max_egress_mbps` is configured.
    pub(super) egress_coordinator: crate::protocol::v2::policy::egress::NodeEgressCoordinatorV1,
    trace_trains: Mutex<HashMap<(u32, u32, u64), mesh::PendingTraceTrainV2>>,
    trace_events: broadcast::Sender<OverlayTraceOamEvent>,
}

impl V2RuntimeState {
    pub(crate) fn new(config: &V2RuntimeConfig, endpoint_id: EndpointId) -> Self {
        let (trace_events, _) = broadcast::channel(256);
        let mut peers = HashMap::default();
        for peer in config.mesh_peers.iter().map(|peer| peer.endpoint_id) {
            peers.insert(
                peer,
                Self::peer_status(&config.tun_name, config.tun_mtu, peer),
            );
        }
        Self {
            endpoint_id,
            started_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            started_at: Instant::now(),
            interface: config.tun_name.clone(),
            tun_mtu: config.tun_mtu,
            peers: RwLock::new(peers),
            connections: RwLock::new(HashMap::default()),
            metrics: RwLock::new(HashMap::default()),
            tun_ingress_metrics: Arc::new(RuntimeMetrics::default()),
            mesh: RwLock::new(crate::status::MeshStatus::default()),
            gateway: crate::status::GatewayStatus {
                transit_enabled: config.transit_enabled,
                subnet_nat_enabled: config.subnet_nat,
                advertised_prefixes: config.advertised_routes.clone(),
            },
            routes: RwLock::new(
                config
                    .routes
                    .iter()
                    .map(|prefix| crate::status::RouteStatus {
                        prefix: prefix.to_string(),
                        present: false,
                    })
                    .collect(),
            ),
            routes_ready: AtomicBool::new(false),
            cpu_utilization_per_mille: AtomicU64::new(0),
            autotune_state_dir: config
                .identity_file
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("autotune"),
            autotune: config.autotune.clone(),
            policy_loader: std::sync::OnceLock::new(),
            max_egress_bytes_per_second: config.max_egress_bytes_per_second,
            egress_coordinator: crate::protocol::v2::policy::egress::NodeEgressCoordinatorV1::new(
                config.max_egress_bytes_per_second.unwrap_or(0),
            ),
            trace_trains: Mutex::new(HashMap::default()),
            trace_events,
        }
    }

    pub(crate) fn subscribe_trace_events(&self) -> broadcast::Receiver<OverlayTraceOamEvent> {
        self.trace_events.subscribe()
    }

    /// Shared loader for external WASM policies. Its engine is built only on
    /// first use by an external live or shadow `.wasm` selection, so the
    /// default native-core `builtin` policy never initializes Wasmtime.
    /// `None` means engine construction failed; an external live selection
    /// then falls back to the native-core builtin policy.
    pub(super) fn policy_loader(&self) -> Option<&PolicyLoader> {
        self.policy_loader
            .get_or_init(|| match PolicyEngine::try_new() {
                Ok(engine) => Some(PolicyLoader::new(engine)),
                Err(error) => {
                    warn!(
                        %error,
                        "policy WASM engine unavailable; .wasm policies fall back to builtin"
                    );
                    None
                }
            })
            .as_ref()
    }
}

pub async fn run(config: V2RuntimeConfig) -> Result<()> {
    // Register SIGTERM before creating routes/firewall state so systemd can
    // never terminate the process in the setup-to-main-loop race window.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing V2 SIGTERM handler")?;
    let result = run_with_shutdown(
        config,
        async move {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => signal.context("waiting for V2 SIGINT"),
                _ = terminate.recv() => Ok(()),
            }
        },
        None,
    )
    .await;
    let cleanup = cleanup_v2_nat_all();
    result.and(cleanup)
}

type ShutdownFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Run the sole production dataplane under an externally owned lifecycle.
///
/// `ironetd` uses this entry point so reload/stop never requires a second
/// protocol runtime. The standalone signal wrapper above is retained only as
/// a developer harness until the temporary benchmark binary is removed.
pub async fn run_with_shutdown<F>(
    config: V2RuntimeConfig,
    shutdown: F,
    ready: Option<oneshot::Sender<()>>,
) -> Result<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    run_with_shutdown_and_state(config, shutdown, ready, None).await
}

pub async fn run_with_shutdown_and_state<F>(
    config: V2RuntimeConfig,
    shutdown: F,
    ready: Option<oneshot::Sender<()>>,
    state: Option<watch::Sender<Option<Arc<V2RuntimeState>>>>,
) -> Result<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    let mut shutdown: ShutdownFuture = Box::pin(shutdown);
    let result = run_with_shutdown_future(config, &mut shutdown, ready, state.as_ref()).await;
    if let Some(state) = state {
        state.send_replace(None);
    }
    result
}

async fn run_with_shutdown_future(
    config: V2RuntimeConfig,
    shutdown: &mut ShutdownFuture,
    mut ready: Option<oneshot::Sender<()>>,
    state: Option<&watch::Sender<Option<Arc<V2RuntimeState>>>>,
) -> Result<()> {
    config.validate()?;
    let secret_key = identity::load(&config.identity_file)?;
    let local_id = secret_key.public();
    let runtime_state = Arc::new(V2RuntimeState::new(&config, local_id));
    let derp_transport = build_v2_derp_transport(&config)?;
    let endpoint = config
        .build_endpoint(secret_key.clone(), derp_transport.clone())
        .await?;
    info!(
        endpoint_id = %local_id,
        bind = %config.bind,
        alpn = "h3",
        cover_profile = COVER_PROFILE_NAME,
        cover_profile_generation = config.cover_profile_id,
        "V2 endpoint ready"
    );
    if let Some(ready) = ready.take() {
        let _ = ready.send(());
    }
    if let Some(state) = state {
        state.send_replace(Some(runtime_state.clone()));
    }

    if config.mesh_peers.is_empty() {
        info!("V2 product endpoint has no admitted peers; waiting fail-closed");
        shutdown.as_mut().await?;
        endpoint.close().await;
        return Ok(());
    }

    run_mesh(
        config,
        endpoint,
        derp_transport,
        secret_key,
        local_id,
        shutdown,
        runtime_state,
    )
    .await
}

#[derive(Debug)]
struct CpuSampler {
    previous_ticks: Option<u64>,
    previous_at: Instant,
    ticks_per_second: u64,
}

pub(super) async fn cpu_sampler_loop(runtime_state: Arc<V2RuntimeState>) -> Result<()> {
    let mut sampler = CpuSampler::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        runtime_state
            .cpu_utilization_per_mille
            .store(u64::from(sampler.sample()), Ordering::Relaxed);
    }
}

impl CpuSampler {
    fn new() -> Self {
        let ticks_per_second = Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(100);
        Self {
            previous_ticks: process_cpu_ticks(),
            previous_at: Instant::now(),
            ticks_per_second,
        }
    }

    fn sample(&mut self) -> u16 {
        let now = Instant::now();
        let current = process_cpu_ticks();
        let value = match (self.previous_ticks, current) {
            (Some(previous), Some(current)) => {
                let elapsed = now
                    .saturating_duration_since(self.previous_at)
                    .as_micros()
                    .max(1);
                u128::from(current.saturating_sub(previous))
                    .saturating_mul(1_000_000)
                    .saturating_mul(1_000)
                    .checked_div(u128::from(self.ticks_per_second).saturating_mul(elapsed))
                    .unwrap_or(u128::MAX)
                    .min(1_000) as u16
            }
            _ => 0,
        };
        self.previous_ticks = current;
        self.previous_at = now;
        value
    }
}

fn process_cpu_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let tail = stat.rsplit_once(") ")?.1;
    let fields = tail.split_ascii_whitespace().collect::<Vec<_>>();
    let user: u64 = fields.get(11)?.parse().ok()?;
    let system: u64 = fields.get(12)?.parse().ok()?;
    Some(user.saturating_add(system))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_tun_merge_budget_is_globally_byte_bounded() {
        assert_eq!(TUN_REGULAR_INPUT_BYTES, 512 * 1024);
    }

    #[test]
    fn cpu_stat_parser_is_available_on_linux() {
        assert!(process_cpu_ticks().is_some());
    }
}
