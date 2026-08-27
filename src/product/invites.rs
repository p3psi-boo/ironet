//! Authority-side invite and password-enrollment membership transactions.

use super::storage::save_invite_transaction;
use super::*;

pub fn create_invite(
    config_path: &Path,
    state_dir: &Path,
    expires_in_secs: Option<u64>,
    direct_addresses: Vec<SocketAddr>,
    member_endpoint_id: Option<EndpointId>,
) -> Result<InviteSummary> {
    create_invite_with_pending_member(
        config_path,
        state_dir,
        expires_in_secs,
        direct_addresses,
        member_endpoint_id,
        false,
    )
}

/// Create the short-lived invite used by a password enrollment. The joining
/// client supplies its persistent public identity, making a dropped response
/// recoverable by retrying with the same local identity.
pub fn create_password_enrollment_invite(
    config_path: &Path,
    state_dir: &Path,
    expires_in_secs: u64,
    direct_addresses: Vec<SocketAddr>,
    member_endpoint_id: EndpointId,
) -> Result<InviteSummary> {
    create_invite_with_pending_member(
        config_path,
        state_dir,
        Some(expires_in_secs),
        direct_addresses,
        Some(member_endpoint_id),
        true,
    )
}

fn create_invite_with_pending_member(
    config_path: &Path,
    state_dir: &Path,
    expires_in_secs: Option<u64>,
    direct_addresses: Vec<SocketAddr>,
    member_endpoint_id: Option<EndpointId>,
    pending_password_enrollment: bool,
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
    let provisioned_peer = if !config
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
        true
    } else {
        false
    };
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
        pending_password_enrollment,
        provisioned_peer: pending_password_enrollment && provisioned_peer,
    });
    save_invite_transaction(config_path, state_dir, &config, &state)?;
    Ok(InviteSummary {
        id,
        token,
        expires_unix_secs: expires,
    })
}

/// Mark a direct password enrollment as permanent after the joiner has
/// safely persisted its local configuration and identity.
pub fn confirm_password_enrollment(
    config_path: &Path,
    state_dir: &Path,
    invite_id: &str,
    member_endpoint_id: EndpointId,
) -> Result<()> {
    let config = load_sealed_sync(config_path)?;
    let mut state = load_state(state_dir)?;
    let invite = state
        .invites
        .iter_mut()
        .find(|invite| invite.id == invite_id)
        .with_context(|| format!("unknown password enrollment {invite_id}"))?;
    ensure!(
        invite.member_endpoint_id == member_endpoint_id,
        "password enrollment {invite_id} belongs to a different node identity"
    );
    ensure!(
        !invite.revoked,
        "password enrollment {invite_id} has already been revoked"
    );
    if !invite.pending_password_enrollment {
        return Ok(());
    }
    ensure!(
        invite.expires_unix_secs >= now_unix()?,
        "password enrollment {invite_id} has expired"
    );
    invite.pending_password_enrollment = false;
    save_invite_transaction(config_path, state_dir, &config, &state)
}

/// Revoke password enrollments which did not complete before their temporary
/// invite deadline. A peer created solely for that provisional enrollment is
/// removed together with its authorization.
pub fn expire_pending_password_enrollments(
    config_path: &Path,
    state_dir: &Path,
    now: u64,
) -> Result<bool> {
    let mut config = load_sealed_sync(config_path)?;
    let mut state = load_state(state_dir)?;
    let mut changed = false;
    for invite in &mut state.invites {
        if invite.pending_password_enrollment && !invite.revoked && invite.expires_unix_secs < now {
            invite.revoked = true;
            changed = true;
        }
    }
    if changed {
        remove_unadmitted_password_peers(&mut config, &state);
        save_invite_transaction(config_path, state_dir, &config, &state)?;
    }
    Ok(changed)
}

/// Revoke an enrollment which could not be activated by the daemon. This is
/// intentionally idempotent so the caller can use it as failure cleanup.
pub fn revoke_password_enrollment(
    config_path: &Path,
    state_dir: &Path,
    invite_id: &str,
) -> Result<()> {
    let mut config = load_sealed_sync(config_path)?;
    let mut state = load_state(state_dir)?;
    let invite = state
        .invites
        .iter_mut()
        .find(|invite| invite.id == invite_id)
        .with_context(|| format!("unknown password enrollment {invite_id}"))?;
    invite.revoked = true;
    remove_unadmitted_password_peers(&mut config, &state);
    save_invite_transaction(config_path, state_dir, &config, &state)
}

fn remove_unadmitted_password_peers(config: &mut Config, state: &ProductState) {
    let provisional = state
        .invites
        .iter()
        .filter(|invite| {
            invite.pending_password_enrollment && invite.provisioned_peer && invite.revoked
        })
        .map(|invite| invite.member_endpoint_id)
        .collect::<HashSet<_>>();
    if provisional.is_empty() {
        return;
    }
    let active = state
        .invites
        .iter()
        .filter(|invite| !invite.revoked)
        .map(|invite| invite.member_endpoint_id)
        .collect::<HashSet<_>>();
    config.peers.retain(|peer| {
        !provisional.contains(&peer.endpoint_id) || active.contains(&peer.endpoint_id)
    });
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
