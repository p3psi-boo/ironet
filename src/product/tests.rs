//! Product workflow regression tests.

use super::*;

#[test]
fn generated_product_config_uses_the_tun_mtu_default() {
    let config = base_config(
        "network-secret".into(),
        "/tmp/ironet-v2.key".into(),
        "edge".into(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
    );
    assert_eq!(config.tun_mtu, crate::config::DEFAULT_TUN_MTU);
}

#[test]
fn local_product_state_is_upgraded_independently_of_the_wire_protocol() {
    let directory = tempfile::tempdir().unwrap();
    let authority = SecretKey::generate().public();
    fs::write(
        state_path(directory.path()),
        format!(
            r#"version = 1
network_name = "deployed-v2"
network_uid = "{authority}"
node_name = "edge"
authority = "{authority}"
address_pool = "21.42.0.0/16"
local_address = "21.42.0.7/32"
created_unix_secs = 1
invites = []
removed_nodes = []
"#
        ),
    )
    .unwrap();

    let state = load_state(directory.path()).unwrap();
    assert_eq!(state.version, PRODUCT_STATE_VERSION);
    assert_eq!(state.ipv6_address_pool, default_ipv6_address_pool());
    assert_eq!(state.local_ipv6_address, None);
}

#[test]
fn invite_round_trip_verifies_signature() {
    let authority = SecretKey::generate();
    let payload = InvitePayload {
        version: INVITE_VERSION,
        id: "invite".into(),
        network_name: "production".into(),
        network_uid: authority.public().to_string(),
        network_secret: "secret".into(),
        authority: authority.public(),
        address_pool: DEFAULT_ADDRESS_POOL.parse().unwrap(),
        ipv6_address_pool: DEFAULT_IPV6_ADDRESS_POOL.parse().unwrap(),
        cover: CoverConfig {
            sni_pool: vec!["video-a.example".into(), "video-b.example".into()],
            profile_id: 9,
        },
        dns_domain: Some("n-test.ironet.internal".into()),
        issued_unix_secs: 1,
        expires_unix_secs: u64::MAX,
        capabilities: vec!["join".into()],
        member_endpoint_id: SecretKey::generate().public(),
        member_secret: None,
        bootstrap: InviteBootstrap {
            name: "edge-a".into(),
            endpoint_id: SecretKey::generate().public(),
            direct_addresses: Vec::new(),
            derp_public_key: None,
        },
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    let mut signed = SignedInvite {
        signature: authority.sign(&bytes).to_bytes().to_vec(),
        payload,
    };
    let token = format!(
        "ironet://join/v2/{}",
        hex::encode(serde_json::to_vec(&signed).unwrap())
    );
    let decoded = decode_invite(&token).unwrap();
    assert_eq!(decoded.network_name, "production");
    assert_eq!(decoded.cover.profile_id, 9);

    // The cover profile is authenticated network control state, not a
    // joiner-local default. Even a correctly signed V2 invite is rejected
    // when that state is structurally invalid.
    signed.payload.cover.sni_pool.clear();
    let bytes = serde_json::to_vec(&signed.payload).unwrap();
    signed.signature = authority.sign(&bytes).to_bytes().to_vec();
    let invalid = format!(
        "ironet://join/v2/{}",
        hex::encode(serde_json::to_vec(&signed).unwrap())
    );
    assert!(
        decode_invite(&invalid)
            .unwrap_err()
            .to_string()
            .contains("cover SNI pool cannot be empty")
    );
}

#[test]
fn removed_invite_generation_is_rejected_without_fallback() {
    let error = decode_invite("ironet://join/v1/00").unwrap_err();
    assert!(error.to_string().contains("expected ironet://join/v2/"));
}

#[test]
fn deterministic_addresses_stay_inside_pool() {
    let pool: Ipv4Net = "100.64.0.0/10".parse().unwrap();
    let key = SecretKey::generate();
    let first = allocate_address(pool, key.public());
    let second = allocate_address(pool, key.public());
    assert_eq!(first, second);
    let IpAddr::V4(address) = first.addr() else {
        panic!("expected IPv4 address")
    };
    assert!(pool.contains(&address));
    assert_eq!(first.prefix_len(), 32);

    let ipv6_pool: Ipv6Net = "fd42:6972:6f68::/64".parse().unwrap();
    let first_ipv6 = allocate_ipv6_address(ipv6_pool, key.public());
    let second_ipv6 = allocate_ipv6_address(ipv6_pool, key.public());
    assert_eq!(first_ipv6, second_ipv6);
    let IpAddr::V6(address) = first_ipv6.addr() else {
        panic!("expected IPv6 address")
    };
    assert!(ipv6_pool.contains(&address));
    assert_eq!(first_ipv6.prefix_len(), 128);
}

#[test]
fn human_durations_are_parsed() {
    assert_eq!(parse_duration("90").unwrap(), 90);
    assert_eq!(parse_duration("15m").unwrap(), 900);
    assert_eq!(parse_duration("2h").unwrap(), 7_200);
    assert!(parse_duration("soon").is_err());
}

#[tokio::test]
async fn create_invite_join_and_capabilities_form_a_complete_product_flow() {
    let creator = tempfile::tempdir().unwrap();
    let joiner = tempfile::tempdir().unwrap();
    let creator_config = creator.path().join("config.toml");
    let joiner_config = joiner.path().join("config.toml");
    let pool: Ipv4Net = "198.18.0.0/16".parse().unwrap();

    let first = create_network(
        &creator_config,
        creator.path(),
        "production",
        CreateNetworkOptions {
            node_name: Some("edge-a".into()),
            address_pool: Some(pool),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(first.created);
    let expected_cover = CoverConfig {
        sni_pool: vec!["edge-video.example".into(), "origin-video.example".into()],
        profile_id: 17,
    };
    update_config(&creator_config, |config| {
        config.cover = expected_cover.clone();
        Ok(())
    })
    .await
    .unwrap();
    let invite = create_invite(
        &creator_config,
        creator.path(),
        Some(60),
        vec!["203.0.113.10:4000".parse().unwrap()],
        None,
    )
    .unwrap();
    let creator_runtime = Config::load(&creator_config).await.unwrap();
    assert_eq!(creator_runtime.peers.len(), 1);
    assert_eq!(
        creator_runtime.peers[0].endpoint_id,
        decode_invite(&invite.token).unwrap().member_endpoint_id
    );
    assert_eq!(decode_invite(&invite.token).unwrap().cover, expected_cover);
    assert!(creator_runtime.peers[0].direct_addresses.is_empty());
    let second = join_network(
        &joiner_config,
        joiner.path(),
        &invite.token,
        Some("edge-b".into()),
        false,
    )
    .await
    .unwrap();
    assert!(!second.created);
    assert_eq!(first.network_id, second.network_id);
    assert_eq!(first.dns_domain, second.dns_domain);
    assert!(
        first
            .dns_domain
            .as_deref()
            .is_some_and(|domain| domain.ends_with(".ironet.internal"))
    );
    assert_ne!(first.address, second.address);
    assert_eq!(first.addresses.len(), 2);
    assert_eq!(second.addresses.len(), 2);
    assert!(
        first
            .addresses
            .iter()
            .any(|address| address.ends_with("/32"))
    );
    assert!(
        first
            .addresses
            .iter()
            .any(|address| address.ends_with("/128"))
    );
    let joiner_runtime = Config::load(&joiner_config).await.unwrap();
    assert_eq!(joiner_runtime.cover, expected_cover);
    assert!(joiner_runtime.dns.enabled);
    assert_eq!(joiner_runtime.dns.domain, first.dns_domain);
    assert_eq!(joiner_runtime.dns.reverse_prefixes.len(), 2);
    assert_eq!(
        joiner_runtime
            .node_addresses
            .iter()
            .filter(|address| address.addr().is_ipv4())
            .count(),
        1
    );
    assert_eq!(
        joiner_runtime
            .node_addresses
            .iter()
            .filter(|address| address.addr().is_ipv6())
            .count(),
        1
    );

    publish_subnet(&creator_config, "192.168.50.0/24".parse().unwrap())
        .await
        .unwrap();
    set_transit(&creator_config, true).await.unwrap();
    rename_local_node(&creator_config, creator.path(), "edge-primary")
        .await
        .unwrap();
    let config = Config::load(&creator_config).await.unwrap();
    assert_eq!(
        config.advertised_prefixes,
        ["192.168.50.0/24".parse().unwrap()]
    );
    assert!(config.routing.transit_enabled);
    assert_eq!(config.node_info.unwrap().name, "edge-primary");

    let repeated = join_network(&joiner_config, joiner.path(), &invite.token, None, false)
        .await
        .unwrap();
    assert_eq!(repeated.endpoint_id, second.endpoint_id);
}

#[tokio::test]
async fn existing_network_queries_do_not_regenerate_a_lost_identity() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    create_network(
        &config_path,
        dir.path(),
        "production",
        CreateNetworkOptions {
            node_name: Some("edge-a".into()),
            address_pool: Some("198.21.0.0/16".parse().unwrap()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let identity_path = dir.path().join("identity.key");
    fs::remove_file(&identity_path).unwrap();

    let error = show_network(&config_path, dir.path()).await.unwrap_err();

    assert!(error.to_string().contains("failed to inspect"));
    assert!(!identity_path.exists());
}

#[tokio::test]
async fn invite_revocation_updates_v2_runtime_admission() {
    let creator = tempfile::tempdir().unwrap();
    let config_path = creator.path().join("config.toml");
    create_network(
        &config_path,
        creator.path(),
        "revocation",
        CreateNetworkOptions {
            node_name: Some("issuer".into()),
            address_pool: Some("198.23.0.0/16".parse().unwrap()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let invite = create_invite(
        &config_path,
        creator.path(),
        Some(60),
        vec!["203.0.113.10:4000".parse().unwrap()],
        None,
    )
    .unwrap();
    let member = decode_invite(&invite.token).unwrap().member_endpoint_id;
    let config = Config::load(&config_path).await.unwrap();
    assert_eq!(
        crate::v2_runtime::V2RuntimeConfig::from_product_config(&config)
            .unwrap()
            .mesh_peers
            .len(),
        1
    );

    revoke_invite(creator.path(), &invite.id).unwrap();
    assert!({
        let runtime = crate::v2_runtime::V2RuntimeConfig::from_product_config(&config).unwrap();
        runtime.mesh_peers.is_empty()
    });

    create_invite(
        &config_path,
        creator.path(),
        Some(60),
        vec!["203.0.113.10:4000".parse().unwrap()],
        Some(member),
    )
    .unwrap();
    let config = Config::load(&config_path).await.unwrap();
    assert_eq!(
        crate::v2_runtime::V2RuntimeConfig::from_product_config(&config)
            .unwrap()
            .mesh_peers
            .len(),
        1
    );
}

#[tokio::test]
async fn setup_rolls_back_when_any_target_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, "owned by another deployment").unwrap();
    let error = create_network(
        &config,
        dir.path(),
        "production",
        CreateNetworkOptions {
            node_name: Some("edge-a".into()),
            address_pool: Some("198.19.0.0/16".parse().unwrap()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("already exists"));
    assert_eq!(
        fs::read_to_string(config).unwrap(),
        "owned by another deployment"
    );
    assert!(!dir.path().join("identity.key").exists());
    assert!(!state_path(dir.path()).exists());
}

#[test]
fn tampered_invite_is_rejected() {
    let authority = SecretKey::generate();
    let payload = InvitePayload {
        version: INVITE_VERSION,
        id: "invite".into(),
        network_name: "production".into(),
        network_uid: authority.public().to_string(),
        network_secret: "secret".into(),
        authority: authority.public(),
        address_pool: DEFAULT_ADDRESS_POOL.parse().unwrap(),
        ipv6_address_pool: DEFAULT_IPV6_ADDRESS_POOL.parse().unwrap(),
        cover: CoverConfig::default(),
        dns_domain: Some("n-test.ironet.internal".into()),
        issued_unix_secs: 1,
        expires_unix_secs: u64::MAX,
        capabilities: vec!["join".into()],
        member_endpoint_id: SecretKey::generate().public(),
        member_secret: None,
        bootstrap: InviteBootstrap {
            name: "edge-a".into(),
            endpoint_id: SecretKey::generate().public(),
            direct_addresses: Vec::new(),
            derp_public_key: None,
        },
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    let mut signed = SignedInvite {
        signature: authority.sign(&bytes).to_bytes().to_vec(),
        payload,
    };
    signed.payload.network_name = "attacker".into();
    let token = format!(
        "ironet://join/v2/{}",
        hex::encode(serde_json::to_vec(&signed).unwrap())
    );
    assert!(decode_invite(&token).is_err());
}

#[tokio::test]
async fn leave_can_preserve_and_reuse_node_identity() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let pool: Ipv4Net = "198.20.0.0/16".parse().unwrap();
    let first = create_network(
        &config,
        dir.path(),
        "first",
        CreateNetworkOptions {
            node_name: Some("edge".into()),
            address_pool: Some(pool),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    leave_network(&config, dir.path(), true).unwrap();
    assert!(dir.path().join("identity.key").exists());
    let second = create_network(
        &config,
        dir.path(),
        "second",
        CreateNetworkOptions {
            node_name: Some("edge".into()),
            address_pool: Some(pool),
            reuse_identity: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(first.endpoint_id, second.endpoint_id);
}
