use std::{
    io,
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
    sync::{Mutex, Semaphore, mpsc, oneshot},
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

struct ListenerUpdate {
    config: Config,
    reply: oneshot::Sender<Result<()>>,
}

#[derive(Clone)]
pub(crate) struct ListenerControl {
    updates: mpsc::Sender<ListenerUpdate>,
}

impl ListenerControl {
    /// Reconcile before the daemon acknowledges a generation change. The
    /// server either installs the complete listener set or keeps the previous
    /// set, so reload and listener state share one commit boundary.
    pub(crate) async fn reconcile(&self, config: Config) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.updates
            .send(ListenerUpdate { config, reply })
            .await
            .map_err(|_| anyhow::anyhow!("password enrollment listener stopped"))?;
        response
            .await
            .context("password enrollment listener dropped reconcile response")?
    }
}

struct ListenerSet {
    addresses: Vec<SocketAddr>,
    listeners: Vec<TcpListener>,
}

impl ListenerSet {
    fn bind(config: &Config) -> Result<Self> {
        let addresses = listener_addresses(config);
        let listeners = bind_listeners(&addresses)?;
        log_listener_state(&listeners)?;
        Ok(Self {
            addresses,
            listeners,
        })
    }

    fn reconcile(&mut self, config: &Config) -> Result<()> {
        let next_addresses = listener_addresses(config);
        if next_addresses == self.addresses {
            return Ok(());
        }

        match bind_listeners(&next_addresses) {
            Ok(next) => self.install(next_addresses, next),
            Err(error) if error_kind(&error) != Some(io::ErrorKind::AddrInUse) => Err(error),
            Err(_) => {
                // Wildcard-to-specific transitions on the same port cannot
                // overlap even with SO_REUSEADDR. Drop the old set only for
                // this known handover case, and restore it if the new bind is
                // rejected for another reason.
                let previous_addresses = self.addresses.clone();
                self.listeners.clear();
                match bind_listeners(&next_addresses) {
                    Ok(next) => self.install(next_addresses, next),
                    Err(error) => match bind_listeners(&previous_addresses) {
                        Ok(previous) => {
                            self.install(previous_addresses, previous)?;
                            Err(error).context(
                                "binding replacement password enrollment listeners; previous listeners restored",
                            )
                        }
                        Err(rollback) => Err(anyhow::anyhow!(
                            "binding replacement password enrollment listeners failed: {error:#}; restoring previous listeners failed: {rollback:#}"
                        )),
                    },
                }
            }
        }
    }

    fn install(&mut self, addresses: Vec<SocketAddr>, listeners: Vec<TcpListener>) -> Result<()> {
        log_listener_state(&listeners)?;
        self.addresses = addresses;
        self.listeners = listeners;
        Ok(())
    }
}

fn error_kind(error: &anyhow::Error) -> Option<io::ErrorKind> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>().map(io::Error::kind))
}

/// Owns the TCP enrollment listeners for the daemon. Authentication handlers
/// may run concurrently; all membership mutations pass through one
/// authority-local committer so config and state never race.
pub(crate) struct ListenerServer {
    config_path: PathBuf,
    command_tx: mpsc::Sender<DaemonCommand>,
    active_config: Config,
    listener_set: ListenerSet,
    updates: mpsc::Receiver<ListenerUpdate>,
}

impl ListenerServer {
    pub(crate) fn bind(
        config_path: PathBuf,
        active_config: Config,
        command_tx: mpsc::Sender<DaemonCommand>,
    ) -> Result<(ListenerControl, Self)> {
        let listener_set = ListenerSet::bind(&active_config)?;
        let (updates, update_rx) = mpsc::channel(4);
        Ok((
            ListenerControl { updates },
            Self {
                config_path,
                command_tx,
                active_config,
                listener_set,
                updates: update_rx,
            },
        ))
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        let connections = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        let committer = Arc::new(Mutex::new(()));
        let mut sweep = time::interval(PENDING_ENROLLMENT_SWEEP);
        sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                update = self.updates.recv() => {
                    let Some(ListenerUpdate { config, reply }) = update else {
                        return Ok(());
                    };
                    let result = self.listener_set.reconcile(&config);
                    if result.is_ok() {
                        self.active_config = config;
                    }
                    let _ = reply.send(result);
                }
                accepted = accept_next(&mut self.listener_set.listeners), if !self.listener_set.listeners.is_empty() => {
                    let (stream, remote) = accepted?;
                    let Ok(permit) = connections.clone().try_acquire_owned() else {
                        warn!(%remote, "password enrollment connection limit reached");
                        continue;
                    };
                    let config_path = self.config_path.clone();
                    let command_tx = self.command_tx.clone();
                    let committer = committer.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_connection(stream, &config_path, command_tx, committer).await {
                            warn!(%remote, %error, "password enrollment request failed")
                        }
                    });
                }
                _ = sweep.tick() => {
                    if self.active_config.password_enrollment.is_some() {
                        // Expiry can request a daemon reload and must never
                        // block the listener-control loop: an enrollment
                        // handler may hold the same committer while waiting
                        // for that reload to reconcile these listeners.
                        let config_path = self.config_path.clone();
                        let config = self.active_config.clone();
                        let command_tx = self.command_tx.clone();
                        let committer = committer.clone();
                        tokio::spawn(async move {
                            if let Err(error) = expire_pending(
                                &config_path,
                                &config,
                                &command_tx,
                                &committer,
                            ).await
                            {
                                warn!(%error, "failed expiring pending password enrollments");
                            }
                        });
                    }
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
