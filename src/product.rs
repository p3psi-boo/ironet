use std::{
    collections::{BTreeMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::{
    config::{
        Config, CoverConfig, DnsConfig, NodeInfo, PeerConfig, RelayConfig, RoutingConfig,
        config_digest_path,
    },
    deployment,
    derp::DerpPublicKey,
    identity,
    routes::RouteRegistry,
};

mod addressing;
mod bootstrap;
mod storage;

use addressing::*;
pub use bootstrap::parse_duration;
use bootstrap::*;
pub use storage::{authority_key_path, default_node_name, load_state, save_state, state_path};
use storage::{
    load_sealed_sync, save_invite_transaction, update_config, update_config_and_state, write_bundle,
};

pub const PRODUCT_STATE_VERSION: u8 = 2;
pub const INVITE_VERSION: u8 = 2;
pub const DEFAULT_ADDRESS_POOL: &str = "100.64.0.0/10";
/// Default pool used for the V2 product address plan.
pub const DEFAULT_IPV6_ADDRESS_POOL: &str = "fd42:6972:6f68::/64";
const PRODUCT_STATE_FILE: &str = "network.toml";
const AUTHORITY_KEY_FILE: &str = "network-authority.key";
const DEFAULT_INVITE_LIFETIME_SECS: u64 = 3_600;

fn default_ipv6_address_pool() -> Ipv6Net {
    DEFAULT_IPV6_ADDRESS_POOL
        .parse()
        .expect("default Overlay IPv6 pool is valid")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductState {
    pub version: u8,
    pub network_name: String,
    pub network_uid: String,
    pub node_name: String,
    pub authority: EndpointId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_key_file: Option<PathBuf>,
    pub address_pool: Ipv4Net,
    pub local_address: IpNet,
    #[serde(default = "default_ipv6_address_pool")]
    pub ipv6_address_pool: Ipv6Net,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ipv6_address: Option<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_invite_id: Option<String>,
    pub created_unix_secs: u64,
    #[serde(default)]
    pub invites: Vec<InviteRecord>,
    #[serde(default)]
    pub removed_nodes: Vec<RemovedNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedNode {
    pub name: String,
    pub endpoint_id: EndpointId,
    pub removed_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRecord {
    pub id: String,
    pub created_unix_secs: u64,
    pub expires_unix_secs: u64,
    #[serde(default)]
    pub revoked: bool,
    /// One-way digest of the bearer token. This permits local revocation checks without storing
    /// the reusable invite itself.
    #[serde(default)]
    pub token_hash: String,
    pub member_endpoint_id: EndpointId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitePayload {
    pub version: u8,
    pub id: String,
    pub network_name: String,
    pub network_uid: String,
    /// V2 SessionHello uses this high-entropy value as its membership secret.
    /// It only appears inside the signed, secret invite token.
    pub network_secret: String,
    pub authority: EndpointId,
    pub address_pool: Ipv4Net,
    pub ipv6_address_pool: Ipv6Net,
    /// Authority-selected network-wide QUIC cover generation. Because this is
    /// inside the signed payload, a joiner cannot silently fall back to a
    /// different SNI pool while still claiming membership in the same V2
    /// network.
    pub cover: CoverConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_domain: Option<String>,
    pub issued_unix_secs: u64,
    pub expires_unix_secs: u64,
    pub capabilities: Vec<String>,
    pub member_endpoint_id: EndpointId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_secret: Option<String>,
    pub bootstrap: InviteBootstrap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteBootstrap {
    pub name: String,
    pub endpoint_id: EndpointId,
    #[serde(default)]
    pub direct_addresses: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_public_key: Option<DerpPublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedInvite {
    payload: InvitePayload,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSummary {
    pub network: String,
    pub network_id: String,
    pub node: String,
    pub endpoint_id: String,
    pub address: String,
    pub addresses: Vec<String>,
    pub dns_domain: Option<String>,
    pub config: String,
    pub state: String,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InviteSummary {
    pub id: String,
    pub token: String,
    pub expires_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeSummary {
    pub name: String,
    pub endpoint_id: String,
    pub local: bool,
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityChange {
    pub capability: String,
    pub value: String,
    pub changed: bool,
    pub applied: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CreateNetworkOptions {
    pub node_name: Option<String>,
    pub address_pool: Option<Ipv4Net>,
    pub ipv6_address_pool: Option<Ipv6Net>,
    pub derp_servers: Vec<String>,
    pub bind_address: Option<SocketAddr>,
    pub dns_domain: Option<String>,
    pub no_dns: bool,
    pub reuse_identity: bool,
}

pub async fn create_network(
    config_path: &Path,
    state_dir: &Path,
    network_name: &str,
    options: CreateNetworkOptions,
) -> Result<NetworkSummary> {
    let CreateNetworkOptions {
        node_name,
        address_pool,
        ipv6_address_pool,
        derp_servers,
        bind_address,
        dns_domain,
        no_dns,
        reuse_identity,
    } = options;
    ensure!(
        !(no_dns && dns_domain.is_some()),
        "--dns-domain conflicts with --no-dns"
    );
    validate_display_name(network_name, "network name")?;
    if state_path(state_dir).exists() && config_path.exists() {
        let existing = load_state(state_dir)?;
        ensure!(
            existing.network_name == network_name,
            "this machine already belongs to network {}",
            existing.network_name
        );
        ensure!(
            existing.authority_key_file.is_some(),
            "this machine joined network {} and is not its creator",
            existing.network_name
        );
        if let Some(node_name) = &node_name {
            ensure!(
                existing.node_name == *node_name,
                "network already exists with node name {}; omit --node-name or use `ironet node rename`",
                existing.node_name
            );
        }
        if let Some(address_pool) = address_pool {
            ensure!(
                existing.address_pool == address_pool,
                "network already uses address pool {}",
                existing.address_pool
            );
        }
        if let Some(ipv6_address_pool) = ipv6_address_pool {
            ensure!(
                existing.ipv6_address_pool == ipv6_address_pool,
                "network already uses IPv6 address pool {}",
                existing.ipv6_address_pool
            );
        }
        let existing_config = Config::load(config_path).await?;
        if no_dns {
            ensure!(
                !existing_config.dns.enabled,
                "network already has embedded DNS enabled"
            );
        }
        if let Some(dns_domain) = &dns_domain {
            ensure!(
                existing_config.dns.enabled
                    && existing_config.dns.domain.as_deref() == Some(dns_domain.as_str()),
                "network already uses DNS domain {}",
                existing_config.dns.domain.as_deref().unwrap_or("disabled")
            );
        }
        return show_network(config_path, state_dir).await;
    }
    let node_name = node_name.unwrap_or_else(default_node_name);
    validate_display_name(&node_name, "node name")?;
    let identity_file = state_dir.join("identity.key");
    let route_file = state_dir.join("routes.toml");
    let product_file = state_path(state_dir);
    let authority_file = authority_key_path(state_dir);
    preflight_new_paths(&[
        config_path,
        &config_digest_path(config_path),
        &route_file,
        &product_file,
        &authority_file,
    ])?;
    if reuse_identity {
        ensure!(
            identity_file.exists(),
            "--reuse-identity requires {}",
            identity_file.display()
        );
    } else {
        preflight_new_paths(&[&identity_file])?;
    }

    let node_key = if reuse_identity {
        identity::load(&identity_file)?
    } else {
        SecretKey::generate()
    };
    let authority_key = SecretKey::generate();
    let pool = match address_pool {
        Some(pool) => {
            validate_address_pool(pool)?;
            ensure_local_pool_available(pool)?;
            pool
        }
        None => select_address_pool(authority_key.public())?,
    };
    let ipv6_pool = match ipv6_address_pool {
        Some(pool) => {
            validate_ipv6_address_pool(pool)?;
            ensure_local_ipv6_pool_available(pool)?;
            pool
        }
        None => select_ipv6_address_pool(authority_key.public())?,
    };
    let network_secret = hex::encode(SecretKey::generate().to_bytes());
    let network_uid = short_network_uid(authority_key.public());
    let address = allocate_address(pool, node_key.public());
    let ipv6_address = allocate_ipv6_address(ipv6_pool, node_key.public());
    let now = now_unix()?;
    let dns = if no_dns {
        DnsConfig::default()
    } else {
        DnsConfig {
            enabled: true,
            domain: Some(dns_domain.unwrap_or_else(|| default_dns_domain(&network_uid))),
            reverse_prefixes: vec![IpNet::V4(pool), IpNet::V6(ipv6_pool)],
            ..DnsConfig::default()
        }
    };
    let mut config = base_config(
        network_secret,
        identity_file.clone(),
        node_name.clone(),
        vec![address, ipv6_address],
        derp_servers,
        bind_address,
        Vec::new(),
    );
    config.dns = dns;
    config.validate()?;
    config.validate_local_id(node_key.public())?;
    let state = ProductState {
        version: PRODUCT_STATE_VERSION,
        network_name: network_name.into(),
        network_uid: network_uid.clone(),
        node_name: node_name.clone(),
        authority: authority_key.public(),
        authority_key_file: Some(authority_file.clone()),
        address_pool: pool,
        local_address: address,
        ipv6_address_pool: ipv6_pool,
        local_ipv6_address: Some(ipv6_address),
        join_invite_id: None,
        created_unix_secs: now,
        invites: Vec::new(),
        removed_nodes: Vec::new(),
    };

    write_bundle(
        config_path,
        state_dir,
        &config,
        &state,
        &node_key,
        !reuse_identity,
        Some((&authority_file, &authority_key)),
    )?;

    Ok(NetworkSummary {
        network: network_name.into(),
        network_id: network_uid,
        node: node_name,
        endpoint_id: node_key.public().to_string(),
        address: address.to_string(),
        addresses: vec![address.to_string(), ipv6_address.to_string()],
        dns_domain: config.dns.domain.clone(),
        config: config_path.display().to_string(),
        state: product_file.display().to_string(),
        created: true,
    })
}

pub fn create_invite(
    config_path: &Path,
    state_dir: &Path,
    expires_in_secs: Option<u64>,
    direct_addresses: Vec<SocketAddr>,
    member_endpoint_id: Option<EndpointId>,
) -> Result<InviteSummary> {
    let mut config = load_sealed_sync(config_path)?;
    config.validate()?;
    let mut state = load_state(state_dir)?;
    let authority_file = state
        .authority_key_file
        .as_deref()
        .context("this node cannot issue invites; no network authority key is installed")?;
    let authority = identity::load(authority_file)?;
    ensure!(
        authority.public() == state.authority,
        "network authority key does not match state"
    );
    let node_key = identity::load(&config.identity_file)?;
    config.validate_local_id(node_key.public())?;
    let now = now_unix()?;
    let lifetime = expires_in_secs.unwrap_or(DEFAULT_INVITE_LIFETIME_SECS);
    ensure!(lifetime > 0, "invite lifetime must be greater than zero");
    let expires = now
        .checked_add(lifetime)
        .context("invite expiry overflow")?;
    let id = hex::encode(&SecretKey::generate().to_bytes()[..12]);
    let generated_member = member_endpoint_id.is_none().then(SecretKey::generate);
    let member_endpoint_id = member_endpoint_id
        .or_else(|| generated_member.as_ref().map(SecretKey::public))
        .expect("member identity is generated or supplied");
    if !config
        .peers
        .iter()
        .any(|peer| peer.endpoint_id == member_endpoint_id)
    {
        config.peers.push(PeerConfig {
            name: format!("invite-{}", &member_endpoint_id.to_string()[..12]),
            endpoint_id: member_endpoint_id,
            direct_addresses: Vec::new(),
            derp_public_key: None,
        });
    }
    config.validate()?;
    config.validate_local_id(node_key.public())?;
    let derp_public_key = if config.relay.derp_enabled() && config.derp_identity_file().exists() {
        Some(crate::derp::identity::load(&config.derp_identity_file())?.public_key())
    } else {
        None
    };
    let payload = InvitePayload {
        version: INVITE_VERSION,
        id: id.clone(),
        network_name: state.network_name.clone(),
        network_uid: state.network_uid.clone(),
        network_secret: config.network_id.clone(),
        authority: state.authority,
        address_pool: state.address_pool,
        ipv6_address_pool: state.ipv6_address_pool,
        cover: config.cover.clone(),
        dns_domain: config.dns.domain.clone(),
        issued_unix_secs: now,
        expires_unix_secs: expires,
        capabilities: vec!["join".into()],
        member_endpoint_id,
        member_secret: generated_member
            .as_ref()
            .map(|key| hex::encode(key.to_bytes())),
        bootstrap: InviteBootstrap {
            name: state.node_name.clone(),
            endpoint_id: node_key.public(),
            direct_addresses,
            derp_public_key,
        },
    };
    let bytes = serde_json::to_vec(&payload)?;
    let signature = authority.sign(&bytes).to_bytes().to_vec();
    let envelope = SignedInvite { payload, signature };
    let token = format!(
        "ironet://join/v2/{}",
        hex::encode(serde_json::to_vec(&envelope)?)
    );
    state.invites.push(InviteRecord {
        id: id.clone(),
        created_unix_secs: now,
        expires_unix_secs: expires,
        revoked: false,
        token_hash: blake3::hash(token.as_bytes()).to_hex().to_string(),
        member_endpoint_id,
    });
    save_invite_transaction(config_path, state_dir, &config, &state)?;
    Ok(InviteSummary {
        id,
        token,
        expires_unix_secs: expires,
    })
}

pub fn list_invites(state_dir: &Path) -> Result<Vec<InviteRecord>> {
    let mut invites = load_state(state_dir)?.invites;
    invites.sort_by_key(|invite| (invite.revoked, invite.expires_unix_secs, invite.id.clone()));
    Ok(invites)
}

pub fn revoke_invite(state_dir: &Path, id: &str) -> Result<bool> {
    let mut state = load_state(state_dir)?;
    let invite = state
        .invites
        .iter_mut()
        .find(|invite| invite.id == id)
        .with_context(|| format!("unknown invite {id}"))?;
    let changed = !invite.revoked;
    invite.revoked = true;
    save_state(state_dir, &state)?;
    Ok(changed)
}

pub async fn join_network(
    config_path: &Path,
    state_dir: &Path,
    token: &str,
    node_name: Option<String>,
    reuse_identity: bool,
) -> Result<NetworkSummary> {
    let payload = decode_invite(token)?;
    if state_path(state_dir).exists() && config_path.exists() {
        let existing = load_state(state_dir)?;
        ensure!(
            existing.network_uid == payload.network_uid,
            "this machine already belongs to network {}",
            existing.network_name
        );
        if let Some(node_name) = &node_name {
            ensure!(
                existing.node_name == *node_name,
                "network already exists with node name {}; omit --node-name or use `ironet node rename`",
                existing.node_name
            );
        }
        return show_network(config_path, state_dir).await;
    }
    let now = now_unix()?;
    ensure!(payload.expires_unix_secs >= now, "invite has expired");
    let node_name = node_name.unwrap_or_else(default_node_name);
    validate_display_name(&node_name, "node name")?;
    validate_address_pool(payload.address_pool)?;
    validate_ipv6_address_pool(payload.ipv6_address_pool)?;
    ensure_local_pool_available(payload.address_pool).with_context(|| {
        format!(
            "invite address pool {} conflicts with this machine; recreate the network with a different --address-pool",
            payload.address_pool
        )
    })?;
    ensure_local_ipv6_pool_available(payload.ipv6_address_pool).with_context(|| {
        format!(
            "invite IPv6 address pool {} conflicts with this machine; recreate the network with a different --ipv6-address-pool",
            payload.ipv6_address_pool
        )
    })?;

    let identity_file = state_dir.join("identity.key");
    let route_file = state_dir.join("routes.toml");
    let product_file = state_path(state_dir);
    preflight_new_paths(&[
        config_path,
        &config_digest_path(config_path),
        &route_file,
        &product_file,
    ])?;
    if reuse_identity {
        ensure!(
            identity_file.exists(),
            "--reuse-identity requires {}",
            identity_file.display()
        );
    } else {
        preflight_new_paths(&[&identity_file])?;
    }
    let node_key = if reuse_identity {
        identity::load(&identity_file)?
    } else {
        payload
            .member_secret
            .as_deref()
            .context("invite is bound to an existing node identity; use --reuse-identity")?
            .parse::<SecretKey>()
            .context("invite contains an invalid member identity")?
    };
    ensure!(
        node_key.public() == payload.member_endpoint_id,
        "invite is bound to member identity {}; local identity is {}",
        payload.member_endpoint_id,
        node_key.public()
    );
    let address = allocate_address(payload.address_pool, node_key.public());
    let ipv6_address = allocate_ipv6_address(payload.ipv6_address_pool, node_key.public());
    let peer = PeerConfig {
        name: payload.bootstrap.name.clone(),
        endpoint_id: payload.bootstrap.endpoint_id,
        direct_addresses: payload.bootstrap.direct_addresses.clone(),
        derp_public_key: payload.bootstrap.derp_public_key,
    };
    let dns = payload
        .dns_domain
        .as_ref()
        .map(|domain| DnsConfig {
            enabled: true,
            domain: Some(domain.clone()),
            reverse_prefixes: vec![
                IpNet::V4(payload.address_pool),
                IpNet::V6(payload.ipv6_address_pool),
            ],
            ..DnsConfig::default()
        })
        .unwrap_or_default();
    let mut config = base_config(
        payload.network_secret,
        identity_file,
        node_name.clone(),
        vec![address, ipv6_address],
        Vec::new(),
        None,
        vec![peer],
    );
    config.cover = payload.cover;
    config.dns = dns;
    config.validate()?;
    config.validate_local_id(node_key.public())?;
    let state = ProductState {
        version: PRODUCT_STATE_VERSION,
        network_name: payload.network_name.clone(),
        network_uid: payload.network_uid.clone(),
        node_name: node_name.clone(),
        authority: payload.authority,
        authority_key_file: None,
        address_pool: payload.address_pool,
        local_address: address,
        ipv6_address_pool: payload.ipv6_address_pool,
        local_ipv6_address: Some(ipv6_address),
        join_invite_id: Some(payload.id.clone()),
        created_unix_secs: now,
        invites: Vec::new(),
        removed_nodes: Vec::new(),
    };
    write_bundle(
        config_path,
        state_dir,
        &config,
        &state,
        &node_key,
        !reuse_identity,
        None,
    )?;
    Ok(NetworkSummary {
        network: payload.network_name,
        network_id: payload.network_uid,
        node: node_name,
        endpoint_id: node_key.public().to_string(),
        address: address.to_string(),
        addresses: vec![address.to_string(), ipv6_address.to_string()],
        dns_domain: config.dns.domain.clone(),
        config: config_path.display().to_string(),
        state: product_file.display().to_string(),
        created: false,
    })
}

pub fn decode_invite(token: &str) -> Result<InvitePayload> {
    let token = token.trim();
    let encoded = token
        .strip_prefix("ironet://join/v2/")
        .context("invalid invite; expected ironet://join/v2/…")?;
    let raw = hex::decode(encoded).context("invite payload is not valid encoding")?;
    let signed: SignedInvite = serde_json::from_slice(&raw).context("invalid invite payload")?;
    ensure!(
        signed.payload.version == INVITE_VERSION,
        "unsupported invite version"
    );
    ensure!(
        signed
            .payload
            .capabilities
            .iter()
            .any(|capability| capability == "join"),
        "invite does not grant the join capability"
    );
    ensure!(
        signed.payload.authority.to_string() == signed.payload.network_uid,
        "invite network identity does not match its authority"
    );
    let signature_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .context("invalid invite signature length")?;
    let signature = Signature::from_bytes(&signature_bytes);
    let bytes = serde_json::to_vec(&signed.payload)?;
    signed
        .payload
        .authority
        .verify(&bytes, &signature)
        .context("invite signature is invalid")?;
    validate_invite_cover(&signed.payload.cover)?;
    Ok(signed.payload)
}

pub async fn show_network(config_path: &Path, state_dir: &Path) -> Result<NetworkSummary> {
    let state = load_state(state_dir)?;
    let config = Config::load(config_path).await?;
    let key = identity::load(&config.identity_file)?;
    Ok(NetworkSummary {
        network: state.network_name,
        network_id: state.network_uid,
        node: state.node_name,
        endpoint_id: key.public().to_string(),
        address: state.local_address.to_string(),
        addresses: config
            .node_addresses
            .iter()
            .map(ToString::to_string)
            .collect(),
        dns_domain: config.dns.domain.clone(),
        config: config_path.display().to_string(),
        state: state_path(state_dir).display().to_string(),
        created: state.authority_key_file.is_some(),
    })
}

pub async fn list_nodes(config_path: &Path, state_dir: &Path) -> Result<Vec<NodeSummary>> {
    let state = load_state(state_dir)?;
    let config = Config::load(config_path).await?;
    let key = identity::load(&config.identity_file)?;
    let mut nodes = vec![NodeSummary {
        name: state.node_name.clone(),
        endpoint_id: key.public().to_string(),
        local: true,
        removed: false,
    }];
    nodes.extend(config.peers.iter().map(|peer| {
        NodeSummary {
            name: peer.name.clone(),
            endpoint_id: peer.endpoint_id.to_string(),
            local: false,
            removed: state
                .removed_nodes
                .iter()
                .any(|removed| removed.endpoint_id == peer.endpoint_id),
        }
    }));
    for removed in &state.removed_nodes {
        if !nodes
            .iter()
            .any(|node| node.endpoint_id == removed.endpoint_id.to_string())
        {
            nodes.push(NodeSummary {
                name: removed.name.clone(),
                endpoint_id: removed.endpoint_id.to_string(),
                local: false,
                removed: true,
            });
        }
    }
    nodes.sort_by_key(|node| (!node.local, node.name.clone(), node.endpoint_id.clone()));
    Ok(nodes)
}

pub async fn rename_local_node(config_path: &Path, state_dir: &Path, name: &str) -> Result<bool> {
    validate_display_name(name, "node name")?;
    let mut state = load_state(state_dir)?;
    let changed = state.node_name != name;
    if !changed {
        return Ok(false);
    }
    state.node_name = name.into();
    update_config_and_state(config_path, state_dir, &state, |config| {
        let mut node_info = config.node_info.take().unwrap_or(NodeInfo {
            name: name.into(),
            description: None,
            metadata: BTreeMap::new(),
        });
        node_info.name = name.into();
        config.node_info = Some(node_info);
        Ok(())
    })
    .await?;
    Ok(true)
}

pub async fn remove_node(
    config_path: &Path,
    state_dir: &Path,
    selector: &str,
) -> Result<(String, bool)> {
    let mut state = load_state(state_dir)?;
    let config = Config::load(config_path).await?;
    if let Some(removed) = state
        .removed_nodes
        .iter()
        .find(|removed| removed.name == selector || removed.endpoint_id.to_string() == selector)
    {
        return Ok((removed.name.clone(), false));
    }
    let peer = config
        .peers
        .iter()
        .find(|peer| peer.name == selector || peer.endpoint_id.to_string() == selector)
        .cloned()
        .with_context(|| format!("unknown configured node {selector}"))?;
    let endpoint = peer.endpoint_id;
    let changed = !state
        .removed_nodes
        .iter()
        .any(|removed| removed.endpoint_id == endpoint);
    if changed {
        state.removed_nodes.push(RemovedNode {
            name: peer.name.clone(),
            endpoint_id: endpoint,
            removed_unix_secs: now_unix()?,
        });
    }
    update_config_and_state(config_path, state_dir, &state, |config| {
        config
            .peers
            .retain(|candidate| candidate.endpoint_id != endpoint);
        Ok(())
    })
    .await?;
    Ok((peer.name, changed))
}

pub async fn remove_node_endpoint(
    config_path: &Path,
    state_dir: &Path,
    endpoint: EndpointId,
    display_name: &str,
) -> Result<(String, bool)> {
    let mut state = load_state(state_dir)?;
    let config = Config::load(config_path).await?;
    let local = identity::load(&config.identity_file)?.public();
    ensure!(
        endpoint != local,
        "use `ironet network leave --yes` to remove this machine"
    );
    let changed = !state
        .removed_nodes
        .iter()
        .any(|removed| removed.endpoint_id == endpoint);
    if changed {
        state.removed_nodes.push(RemovedNode {
            name: display_name.to_owned(),
            endpoint_id: endpoint,
            removed_unix_secs: now_unix()?,
        });
    }
    update_config_and_state(config_path, state_dir, &state, |config| {
        config
            .peers
            .retain(|candidate| candidate.endpoint_id != endpoint);
        Ok(())
    })
    .await?;
    Ok((display_name.to_owned(), changed))
}

pub fn node_is_removed(identity_file: &Path, endpoint: EndpointId) -> bool {
    removed_node_ids(identity_file).contains(&endpoint)
}

pub fn removed_node_ids(identity_file: &Path) -> HashSet<EndpointId> {
    let Some(state_dir) = identity_file.parent() else {
        return HashSet::new();
    };
    load_state(state_dir)
        .map(|state| {
            state
                .removed_nodes
                .iter()
                .map(|removed| removed.endpoint_id)
                .collect()
        })
        .unwrap_or_default()
}

pub fn local_invite_id(identity_file: &Path) -> Option<String> {
    let state_dir = identity_file.parent()?;
    load_state(state_dir).ok()?.join_invite_id
}

pub fn authority_invites(identity_file: &Path) -> Option<BTreeMap<String, (EndpointId, bool)>> {
    let state_dir = identity_file.parent()?;
    let state = load_state(state_dir).ok()?;
    state.authority_key_file.as_ref()?;
    Some(
        state
            .invites
            .into_iter()
            .map(|invite| (invite.id, (invite.member_endpoint_id, invite.revoked)))
            .collect(),
    )
}

pub async fn publish_subnet(config_path: &Path, prefix: IpNet) -> Result<CapabilityChange> {
    let mut changed = false;
    update_config(config_path, |config| {
        if !config.advertised_prefixes.contains(&prefix) {
            config.advertised_prefixes.push(prefix);
            changed = true;
        }
        config.routing.nat_enabled = true;
        Ok(())
    })
    .await?;
    Ok(CapabilityChange {
        capability: "subnet".into(),
        value: prefix.to_string(),
        changed,
        applied: false,
    })
}

pub async fn unpublish_subnet(config_path: &Path, prefix: IpNet) -> Result<CapabilityChange> {
    let mut changed = false;
    update_config(config_path, |config| {
        let before = config.advertised_prefixes.len();
        config
            .advertised_prefixes
            .retain(|candidate| *candidate != prefix);
        changed = before != config.advertised_prefixes.len();
        Ok(())
    })
    .await?;
    Ok(CapabilityChange {
        capability: "subnet".into(),
        value: prefix.to_string(),
        changed,
        applied: false,
    })
}

pub async fn list_subnets(config_path: &Path) -> Result<Vec<IpNet>> {
    let mut values = Config::load(config_path).await?.advertised_prefixes;
    values.sort_by_key(ToString::to_string);
    Ok(values)
}

pub async fn set_transit(config_path: &Path, enabled: bool) -> Result<CapabilityChange> {
    let mut changed = false;
    update_config(config_path, |config| {
        changed = config.routing.transit_enabled != enabled;
        config.routing.transit_enabled = enabled;
        Ok(())
    })
    .await?;
    Ok(CapabilityChange {
        capability: "transit".into(),
        value: enabled.to_string(),
        changed,
        applied: false,
    })
}

pub fn leave_network(
    config_path: &Path,
    state_dir: &Path,
    keep_identity: bool,
) -> Result<Vec<PathBuf>> {
    if !state_path(state_dir).exists() {
        return Ok(Vec::new());
    }
    let state = load_state(state_dir)?;
    let config = load_sealed_sync(config_path)?;
    let mut paths = vec![
        config_path.to_path_buf(),
        config_digest_path(config_path),
        config.route_registry_path(),
        state_path(state_dir),
    ];
    if let Some(authority) = state.authority_key_file {
        paths.push(authority);
    }
    if !keep_identity {
        paths.push(config.derp_identity_file());
        paths.push(config.identity_file);
    }
    let mut removed = Vec::new();
    for path in paths {
        match fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed removing {}", path.display()));
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests;
