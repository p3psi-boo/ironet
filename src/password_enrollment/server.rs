use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, mpsc, oneshot, watch},
    time::{self, MissedTickBehavior},
};
use tracing::{info, warn};

use crate::{
    config::Config,
    control::{DaemonCommand, RpcError},
    product,
};

use super::protocol::{
    EnrollmentChallenge, EnrollmentProof, EnrollmentRequest, EnrollmentResult, PASSWORD_KEY_BYTES,
    PASSWORD_SALT_BYTES, PROTOCOL_VERSION, decode_fixed, encrypt_invite, proof_is_valid,
    random_bytes, read_json, rejection_result, successful_result, write_json,
};

const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const PENDING_ENROLLMENT_SWEEP: Duration = Duration::from_secs(30);

type Committer = Arc<Mutex<()>>;

/// Reconciles the TCP enrollment listener with the daemon's active Config.
/// Authentication handlers may run concurrently; all membership mutations pass
/// through one authority-local committer so config and state never race.
pub async fn serve(
    config_path: PathBuf,
    mut active_config: watch::Receiver<Config>,
    command_tx: mpsc::Sender<DaemonCommand>,
) -> Result<()> {
    let mut bound_addresses = listener_addresses(&active_config.borrow());
    let mut listeners = bind_listeners(&bound_addresses)?;
    log_listener_state(&listeners)?;
    let connections = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let committer = Arc::new(Mutex::new(()));
    let mut sweep = time::interval(PENDING_ENROLLMENT_SWEEP);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            changed = active_config.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                let next_addresses = listener_addresses(&active_config.borrow());
                if next_addresses != bound_addresses {
                    listeners = bind_listeners(&next_addresses)?;
                    bound_addresses = next_addresses;
                    log_listener_state(&listeners)?;
                }
            }
            accepted = accept_next(&mut listeners), if !listeners.is_empty() => {
                let (stream, remote) = accepted?;
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    warn!(%remote, "password enrollment connection limit reached");
                    continue;
                };
                let config_path = config_path.clone();
                let command_tx = command_tx.clone();
                let committer = committer.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_connection(stream, &config_path, command_tx, committer).await {
                        warn!(%remote, %error, "password enrollment request failed")
                    }
                });
            }
            _ = sweep.tick() => {
                let config = active_config.borrow().clone();
                if config.password_enrollment.is_some()
                    && let Err(error) = expire_pending(&config_path, &config, &command_tx, &committer).await
                {
                    warn!(%error, "failed expiring pending password enrollments");
                }
            }
        }
    }
}

pub(super) async fn handle_connection(
    stream: TcpStream,
    config_path: &Path,
    command_tx: mpsc::Sender<DaemonCommand>,
    committer: Committer,
) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let request: EnrollmentRequest = read_json(&mut read).await?;
    ensure!(
        request.version() == PROTOCOL_VERSION,
        "unsupported password enrollment protocol version {}",
        request.version()
    );

    let config = Config::load(config_path).await?;
    let enrollment = config
        .password_enrollment
        .as_ref()
        .context("password enrollment is not enabled for this network")?;
    enrollment.validate()?;
    let salt = decode_fixed::<PASSWORD_SALT_BYTES>(&enrollment.salt, "configured password salt")?;
    let key =
        decode_fixed::<PASSWORD_KEY_BYTES>(&enrollment.password_key, "configured password key")?;
    let nonce = random_bytes::<32>()?;
    write_json(
        &mut write,
        &EnrollmentChallenge {
            version: PROTOCOL_VERSION,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
        },
    )
    .await?;

    let proof: EnrollmentProof = read_json(&mut read).await?;
    let proof = decode_fixed::<PASSWORD_KEY_BYTES>(&proof.proof, "password proof")?;
    if !proof_is_valid(&key, &nonce, &request, &proof) {
        write_rejection(&mut write).await?;
        return Ok(());
    }

    let state_dir = config
        .identity_file
        .parent()
        .context("password enrollment identity file has no parent directory")?
        .to_path_buf();
    match request {
        EnrollmentRequest::Join {
            bootstrap,
            member_endpoint_id,
            ..
        } => {
            let invite = issue_enrollment(
                config_path,
                &state_dir,
                enrollment.invite_ttl_secs,
                bootstrap,
                member_endpoint_id,
                &command_tx,
                &committer,
            )
            .await?;
            let (invite_nonce, encrypted_invite) = encrypt_invite(&key, &invite.token)?;
            write_json(
                &mut write,
                &EnrollmentResult {
                    version: PROTOCOL_VERSION,
                    invite_id: Some(invite.id),
                    invite_nonce: Some(invite_nonce),
                    encrypted_invite: Some(encrypted_invite),
                    error: None,
                },
            )
            .await?;
        }
        EnrollmentRequest::Confirm {
            invite_id,
            member_endpoint_id,
            ..
        } => {
            confirm_enrollment(
                config_path,
                &state_dir,
                &invite_id,
                member_endpoint_id,
                &committer,
            )
            .await?;
            write_json(&mut write, &successful_result()).await?;
        }
    }
    write.shutdown().await?;
    Ok(())
}

async fn issue_enrollment(
    config_path: &Path,
    state_dir: &Path,
    invite_ttl_secs: u64,
    bootstrap: SocketAddr,
    member_endpoint_id: iroh::EndpointId,
    command_tx: &mpsc::Sender<DaemonCommand>,
    committer: &Committer,
) -> Result<product::InviteSummary> {
    let _commit = committer.lock().await;
    expire_pending_locked(config_path, state_dir, command_tx).await?;
    let config_path = config_path.to_path_buf();
    let state_dir = state_dir.to_path_buf();
    let invite_config_path = config_path.clone();
    let invite_state_dir = state_dir.clone();
    let invite = tokio::task::spawn_blocking(move || {
        product::create_password_enrollment_invite(
            &invite_config_path,
            &invite_state_dir,
            invite_ttl_secs,
            vec![bootstrap],
            member_endpoint_id,
        )
    })
    .await
    .context("password enrollment invite worker panicked")??;
    if let Err(error) = reload_after_enrollment(command_tx).await {
        rollback_enrollment(
            config_path.as_path(),
            state_dir.as_path(),
            &invite.id,
            command_tx,
        )
        .await;
        return Err(error);
    }
    Ok(invite)
}

async fn confirm_enrollment(
    config_path: &Path,
    state_dir: &Path,
    invite_id: &str,
    member_endpoint_id: iroh::EndpointId,
    committer: &Committer,
) -> Result<()> {
    let _commit = committer.lock().await;
    let config_path = config_path.to_path_buf();
    let state_dir = state_dir.to_path_buf();
    let invite_id = invite_id.to_owned();
    tokio::task::spawn_blocking(move || {
        product::confirm_password_enrollment(
            &config_path,
            &state_dir,
            &invite_id,
            member_endpoint_id,
        )
    })
    .await
    .context("password enrollment confirmation worker panicked")??;
    Ok(())
}

async fn expire_pending(
    config_path: &Path,
    config: &Config,
    command_tx: &mpsc::Sender<DaemonCommand>,
    committer: &Committer,
) -> Result<()> {
    let state_dir = config
        .identity_file
        .parent()
        .context("password enrollment identity file has no parent directory")?;
    let _commit = committer.lock().await;
    expire_pending_locked(config_path, state_dir, command_tx).await
}

async fn expire_pending_locked(
    config_path: &Path,
    state_dir: &Path,
    command_tx: &mpsc::Sender<DaemonCommand>,
) -> Result<()> {
    let config_path = config_path.to_path_buf();
    let state_dir = state_dir.to_path_buf();
    let changed = tokio::task::spawn_blocking(move || {
        product::expire_pending_password_enrollments(&config_path, &state_dir, now_unix_secs())
    })
    .await
    .context("password enrollment expiry worker panicked")??;
    if changed {
        reload_after_enrollment(command_tx).await?;
    }
    Ok(())
}

async fn rollback_enrollment(
    config_path: &Path,
    state_dir: &Path,
    invite_id: &str,
    command_tx: &mpsc::Sender<DaemonCommand>,
) {
    let config_path = config_path.to_path_buf();
    let state_dir = state_dir.to_path_buf();
    let invite_id = invite_id.to_owned();
    if let Err(error) = tokio::task::spawn_blocking(move || {
        product::revoke_password_enrollment(&config_path, &state_dir, &invite_id)
    })
    .await
    .context("password enrollment rollback worker panicked")
    .and_then(|result| result)
    {
        warn!(%error, "failed rolling back password enrollment");
        return;
    }
    if let Err(error) = reload_after_enrollment(command_tx).await {
        warn!(%error, "failed reloading after password enrollment rollback");
    }
}

async fn reload_after_enrollment(command_tx: &mpsc::Sender<DaemonCommand>) -> Result<()> {
    let (reply, response) = oneshot::channel();
    command_tx
        .send(DaemonCommand::Reload { reply })
        .await
        .map_err(|_| anyhow::anyhow!("password enrollment daemon supervisor stopped"))?;
    match response
        .await
        .context("password enrollment daemon dropped reload response")?
    {
        Ok(_) => Ok(()),
        Err(RpcError { code, message }) => bail!("password enrollment reload {code}: {message}"),
    }
}

async fn write_rejection<W: tokio::io::AsyncWrite + Unpin>(write: &mut W) -> Result<()> {
    write_json(write, &rejection_result()).await?;
    write.shutdown().await?;
    Ok(())
}

pub(super) fn listener_addresses(config: &Config) -> Vec<SocketAddr> {
    config
        .password_enrollment
        .as_ref()
        .map(|_| {
            let bind = config
                .endpoint_bind_addresses()
                .next()
                .unwrap_or_else(|| "[::]:4000".parse().expect("static V2 bind address"));
            enrollment_bind_addresses(bind)
        })
        .unwrap_or_default()
}

fn bind_listeners(addresses: &[SocketAddr]) -> Result<Vec<TcpListener>> {
    addresses.iter().copied().map(bind_listener).collect()
}

fn log_listener_state(listeners: &[TcpListener]) -> Result<()> {
    if listeners.is_empty() {
        return Ok(());
    }
    let addresses = listeners
        .iter()
        .map(|listener| listener.local_addr().map(|address| address.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    info!(addresses = ?addresses, "password enrollment listener ready");
    Ok(())
}

pub(super) fn enrollment_bind_addresses(bind: SocketAddr) -> Vec<SocketAddr> {
    match bind.ip() {
        IpAddr::V4(address) if address.is_unspecified() => vec![
            bind,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), bind.port()),
        ],
        IpAddr::V6(address) if address.is_unspecified() => vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bind.port()),
            bind,
        ],
        _ => vec![bind],
    }
}

fn bind_listener(address: SocketAddr) -> Result<TcpListener> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.listen(64)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into()).context("creating password enrollment listener")
}

async fn accept_next(listeners: &mut [TcpListener]) -> Result<(TcpStream, SocketAddr)> {
    match listeners {
        [listener] => listener
            .accept()
            .await
            .context("accepting password enrollment connection"),
        [first, second] => tokio::select! {
            accepted = first.accept() => accepted.context("accepting password enrollment connection"),
            accepted = second.accept() => accepted.context("accepting password enrollment connection"),
        },
        _ => unreachable!("password enrollment has zero, one, or two listeners"),
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
