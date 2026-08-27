//! Shared network-create and join bootstrap helpers.

use super::*;

pub(super) fn validate_invite_cover(cover: &CoverConfig) -> Result<()> {
    ensure!(
        cover.profile_id != 0,
        "invite cover generation zero is reserved"
    );
    ensure!(
        !cover.sni_pool.is_empty(),
        "invite cover SNI pool cannot be empty"
    );
    let mut names = HashSet::new();
    for name in &cover.sni_pool {
        crate::v2_runtime::validate_cover_sni(name)?;
        ensure!(names.insert(name), "duplicate invite cover SNI {name}");
    }
    Ok(())
}

pub(super) fn base_config(
    network_secret: String,
    identity_file: PathBuf,
    node_name: String,
    addresses: Vec<IpNet>,
    derp_servers: Vec<String>,
    bind_address: Option<SocketAddr>,
    peers: Vec<PeerConfig>,
) -> Config {
    Config {
        network_id: network_secret,
        identity_file,
        bind_addresses: bind_address.into_iter().collect(),
        excluded_underlay_prefixes: Vec::new(),
        tun_mtu: crate::config::DEFAULT_TUN_MTU,
        node_interface: "ironet0".into(),
        node_addresses: addresses,
        advertised_prefixes: Vec::new(),
        node_info: Some(NodeInfo {
            name: node_name,
            description: None,
            metadata: BTreeMap::new(),
        }),
        relay: RelayConfig {
            servers: derp_servers,
        },
        cover: crate::config::CoverConfig::default(),
        peers,
        links: Vec::new(),
        route_origins: Vec::new(),
        routing: RoutingConfig::default(),
        mesh: Default::default(),
        dns: DnsConfig::default(),
        autotune: Default::default(),
        path_migration: Default::default(),
        password_enrollment: None,
    }
}

pub(super) fn preflight_new_paths(paths: &[&Path]) -> Result<()> {
    for path in paths {
        ensure!(
            !path.exists(),
            "network state already exists at {}",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn validate_display_name(value: &str, kind: &str) -> Result<()> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{kind} cannot be empty");
    ensure!(value.len() <= 63, "{kind} cannot exceed 63 bytes");
    ensure!(
        value
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || matches!(character, '-' | '_' | '.')),
        "{kind} may only contain letters, digits, '.', '_' and '-'"
    );
    Ok(())
}

pub(super) fn short_network_uid(authority: EndpointId) -> String {
    authority.to_string()
}

pub(super) fn default_dns_domain(network_uid: &str) -> String {
    let short = network_uid.get(..12).unwrap_or(network_uid);
    format!("n-{short}.ironet.internal")
}

pub(super) fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

pub fn parse_duration(value: &str) -> Result<u64> {
    let value = value.trim();
    ensure!(!value.is_empty(), "duration cannot be empty");
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's') => (&value[..value.len() - 1], 1),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3_600),
        Some(b'd') => (&value[..value.len() - 1], 86_400),
        Some(byte) if byte.is_ascii_digit() => (value, 1),
        _ => bail!("duration must use s, m, h or d, for example 1h"),
    };
    let number = u64::from_str(number).context("invalid duration")?;
    number
        .checked_mul(multiplier)
        .context("duration is too large")
}
