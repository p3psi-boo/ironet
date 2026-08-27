use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::{
    io::{AsyncWrite, BufReader},
    net::{UnixListener, UnixStream, unix::OwnedWriteHalf},
    sync::{Mutex, Notify, Semaphore, mpsc, oneshot, watch},
    time,
};
use tracing::{info, warn};

use crate::{
    config::Config,
    extensions::{self, ExtensionState},
    json_line,
    status::{PeerStatus, RuntimeStatus},
    trace::{self, PingResult, PingSample, TraceHop, TraceResult},
};
use ironet_extension_sdk::{
    ApiLimits, ApplyRoutesRequest, Capability, CapabilitySet, Client as ControlClient,
    DeleteRoutesRequest, EventWatchAck, ExtensionEvent,
    MAX_CONTROL_REQUEST_BYTES as MAX_REQUEST_BYTES,
    MAX_CONTROL_RESPONSE_BYTES as MAX_RESPONSE_BYTES, ResponseStream as ControlResponseStream,
    RouteMutationResult,
};
pub use ironet_extension_sdk::{
    CONTROL_API_VERSION as CONTROL_PROTOCOL_VERSION, DEFAULT_CONTROL_SOCKET, RpcError,
};

const MAX_CONTROL_CONNECTIONS: usize = 64;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TRACE_HOP_TIMEOUT: Duration = Duration::from_secs(60);
const EVENT_HISTORY_LIMIT: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadAck {
    pub generation: u64,
    pub endpoint_id: String,
}

pub enum DaemonCommand {
    Reload {
        reply: oneshot::Sender<std::result::Result<ReloadAck, RpcError>>,
    },
    #[doc(hidden)]
    Stop { reply: oneshot::Sender<()> },
}

#[derive(Debug, Default)]
struct EventLogState {
    next_cursor: u64,
    events: VecDeque<ExtensionEvent>,
}

/// Bounded replay log for extension events. Producers never wait for consumers;
/// a consumer that falls behind receives `cursor_expired` and resynchronizes
/// from `get_snapshot`.
#[derive(Debug, Default)]
pub struct EventLog {
    state: Mutex<EventLogState>,
    changed: Notify,
}

impl EventLog {
    pub async fn publish(
        &self,
        kind: impl Into<String>,
        resource: Option<String>,
        data: Value,
    ) -> ExtensionEvent {
        let mut state = self.state.lock().await;
        state.next_cursor = state.next_cursor.saturating_add(1);
        let event = ExtensionEvent {
            cursor: state.next_cursor,
            emitted_unix_millis: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            kind: kind.into(),
            resource,
            data,
        };
        state.events.push_back(event.clone());
        if state.events.len() > EVENT_HISTORY_LIMIT {
            state.events.pop_front();
        }
        drop(state);
        self.changed.notify_waiters();
        event
    }

    async fn bounds(&self) -> EventWatchAck {
        let state = self.state.lock().await;
        EventWatchAck {
            current_cursor: state.next_cursor,
            oldest_cursor: state
                .events
                .front()
                .map_or(state.next_cursor.saturating_add(1), |event| event.cursor),
        }
    }

    async fn after(&self, cursor: u64) -> std::result::Result<Vec<ExtensionEvent>, RpcError> {
        let state = self.state.lock().await;
        if cursor > state.next_cursor {
            return Err(RpcError::new(
                "cursor_invalid",
                format!(
                    "event cursor {cursor} is ahead of current cursor {}; fetch get_snapshot before resuming",
                    state.next_cursor
                ),
            ));
        }
        let oldest = state
            .events
            .front()
            .map_or(state.next_cursor.saturating_add(1), |event| event.cursor);
        if cursor.saturating_add(1) < oldest {
            return Err(RpcError::new(
                "cursor_expired",
                format!(
                    "event cursor {cursor} is older than retained cursor {oldest}; fetch get_snapshot and resume from the current cursor"
                ),
            ));
        }
        Ok(state
            .events
            .iter()
            .filter(|event| event.cursor > cursor)
            .cloned()
            .collect())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    version: u16,
    id: u64,
    #[serde(flatten)]
    method: Method,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum Method {
    GetCapabilities,
    GetSnapshot,
    WatchEvents {
        after_cursor: Option<u64>,
    },
    ListRoutes,
    ApplyRoutes {
        #[serde(flatten)]
        request: ApplyRoutesRequest,
    },
    DeleteRoutes {
        #[serde(flatten)]
        request: DeleteRoutesRequest,
    },
    Snapshot,
    Status,
    Peers,
    Health,
    Ping {
        target: IpAddr,
        count: u16,
        timeout_ms: u64,
    },
    Trace {
        target: IpAddr,
        max_hops: u8,
        timeout_ms: u64,
    },
    Reload,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum ServerMessage {
    Result {
        version: u16,
        id: u64,
        result: Value,
    },
    Error {
        version: u16,
        id: u64,
        error: RpcError,
    },
    PingSample {
        version: u16,
        id: u64,
        sample: PingSample,
    },
    PingDone {
        version: u16,
        id: u64,
        result: PingResult,
    },
    TraceHop {
        version: u16,
        id: u64,
        hop: TraceHop,
    },
    TraceDone {
        version: u16,
        id: u64,
        result: TraceResult,
    },
    ExtensionEvent {
        version: u16,
        id: u64,
        extension_event: ExtensionEvent,
    },
}

#[derive(Debug, Clone, Copy)]
struct PeerIdentity {
    pid: Option<i32>,
    uid: u32,
    gid: u32,
}

pub async fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed creating control directory {}", parent.display()))?;
    }
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_socket(),
                "refusing to replace non-socket control path {}",
                path.display()
            );
            tokio::fs::remove_file(path)
                .await
                .with_context(|| format!("failed removing stale socket {}", path.display()))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed inspecting control socket {}", path.display()));
        }
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed binding control socket {}", path.display()))?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .await
        .with_context(|| format!("failed setting control socket mode on {}", path.display()))?;
    Ok(listener)
}

pub async fn serve(
    listener: UnixListener,
    socket_path: PathBuf,
    active_config: watch::Receiver<Config>,
    command_tx: mpsc::Sender<DaemonCommand>,
    runtime_state: watch::Receiver<Option<Arc<crate::v2_runtime::V2RuntimeState>>>,
    events: Arc<EventLog>,
) -> Result<()> {
    let owner_uid = tokio::fs::metadata(&socket_path)
        .await
        .with_context(|| format!("failed reading metadata for {}", socket_path.display()))?
        .uid();
    let connection_slots = Arc::new(Semaphore::new(MAX_CONTROL_CONNECTIONS));
    info!(socket = %socket_path.display(), mode = "0660", "control socket ready");
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("failed accepting control connection")?;
        let slot = connection_slots
            .clone()
            .acquire_owned()
            .await
            .context("control connection limiter closed")?;
        let credentials = stream
            .peer_cred()
            .context("failed reading Unix peer credentials")?;
        let peer = PeerIdentity {
            pid: credentials.pid(),
            uid: credentials.uid(),
            gid: credentials.gid(),
        };
        let active_config = active_config.clone();
        let command_tx = command_tx.clone();
        let runtime_state = runtime_state.clone();
        let events = events.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(error) = handle_connection(
                stream,
                peer,
                owner_uid,
                active_config,
                command_tx,
                runtime_state,
                events,
            )
            .await
            {
                warn!(
                    peer_pid = ?peer.pid,
                    peer_uid = peer.uid,
                    peer_gid = peer.gid,
                    %error,
                    "control request failed"
                );
            }
        });
    }
}

async fn handle_connection(
    stream: UnixStream,
    peer: PeerIdentity,
    owner_uid: u32,
    active_config: watch::Receiver<Config>,
    command_tx: mpsc::Sender<DaemonCommand>,
    runtime_state: watch::Receiver<Option<Arc<crate::v2_runtime::V2RuntimeState>>>,
    events: Arc<EventLog>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let line = time::timeout(
        REQUEST_READ_TIMEOUT,
        json_line::read_bounded_line(&mut reader, MAX_REQUEST_BYTES),
    )
    .await
    .context("timed out reading control request")??;
    ensure!(!line.is_empty(), "empty control request");
    let request: Request = match serde_json::from_slice(&line) {
        Ok(request) => request,
        Err(error) => {
            send_error(
                &mut writer,
                0,
                RpcError::new("invalid_request", format!("invalid JSON request: {error}")),
            )
            .await?;
            return Ok(());
        }
    };
    if request.version != CONTROL_PROTOCOL_VERSION {
        send_error(
            &mut writer,
            request.id,
            RpcError::new(
                "unsupported_version",
                format!(
                    "control protocol {} is unsupported; expected {}",
                    request.version, CONTROL_PROTOCOL_VERSION
                ),
            ),
        )
        .await?;
        return Ok(());
    }

    info!(
        peer_pid = ?peer.pid,
        peer_uid = peer.uid,
        peer_gid = peer.gid,
        request_id = request.id,
        method = method_name(&request.method),
        "control request"
    );
    match request.method {
        Method::GetCapabilities => {
            send_result(&mut writer, request.id, &capabilities()).await?;
        }
        Method::GetSnapshot => {
            let state = runtime_state.borrow().clone();
            match state {
                Some(state) => match state.live_snapshot().await {
                    Ok(status) => {
                        let config = active_config.borrow().clone();
                        let routes = load_extension_routes(&config).await?;
                        let cursor = events.bounds().await.current_cursor;
                        send_result(
                            &mut writer,
                            request.id,
                            &serde_json::json!({
                                "api_version": CONTROL_PROTOCOL_VERSION,
                                "event_cursor": cursor,
                                "runtime": status,
                                "desired_routes": routes,
                            }),
                        )
                        .await?
                    }
                    Err(error) => {
                        send_error(
                            &mut writer,
                            request.id,
                            RpcError::new("snapshot_failed", error.to_string()),
                        )
                        .await?
                    }
                },
                None => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("runtime_unavailable", "data plane is not active"),
                    )
                    .await?
                }
            }
        }
        Method::WatchEvents { after_cursor } => {
            let bounds = events.bounds().await;
            let mut cursor = after_cursor.unwrap_or(bounds.current_cursor);
            if let Err(error) = events.after(cursor).await {
                send_error(&mut writer, request.id, error).await?;
                return Ok(());
            }
            send_result(&mut writer, request.id, &bounds).await?;
            loop {
                let notified = events.changed.notified();
                match events.after(cursor).await {
                    Ok(pending) => {
                        for event in pending {
                            cursor = event.cursor;
                            send_message(
                                &mut writer,
                                &ServerMessage::ExtensionEvent {
                                    version: CONTROL_PROTOCOL_VERSION,
                                    id: request.id,
                                    extension_event: event,
                                },
                            )
                            .await?;
                        }
                    }
                    Err(error) => {
                        send_error(&mut writer, request.id, error).await?;
                        return Ok(());
                    }
                }
                notified.await;
            }
        }
        Method::ListRoutes => {
            let config = active_config.borrow().clone();
            send_result(
                &mut writer,
                request.id,
                &load_extension_routes(&config).await?,
            )
            .await?;
        }
        Method::ApplyRoutes { request: change } => {
            if !can_mutate(peer, owner_uid) {
                send_error(
                    &mut writer,
                    request.id,
                    RpcError::new(
                        "permission_denied",
                        "route mutation requires root or the daemon service user",
                    ),
                )
                .await?;
                return Ok(());
            }
            let config = active_config.borrow().clone();
            match mutate_extension_routes(
                &config,
                change.dry_run,
                |state, now| state.apply(&change, now),
                &command_tx,
            )
            .await
            {
                Ok(result) => {
                    if !result.dry_run && result.changed > 0 {
                        events
                            .publish("route.applied", None, serde_json::to_value(&result)?)
                            .await;
                    }
                    send_result(&mut writer, request.id, &result).await?
                }
                Err(error) => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("route_rejected", error.to_string()),
                    )
                    .await?
                }
            }
        }
        Method::DeleteRoutes { request: change } => {
            if !can_mutate(peer, owner_uid) {
                send_error(
                    &mut writer,
                    request.id,
                    RpcError::new(
                        "permission_denied",
                        "route mutation requires root or the daemon service user",
                    ),
                )
                .await?;
                return Ok(());
            }
            let config = active_config.borrow().clone();
            match mutate_extension_routes(
                &config,
                change.dry_run,
                |state, now| state.delete(&change, now),
                &command_tx,
            )
            .await
            {
                Ok(result) => {
                    if !result.dry_run && result.changed > 0 {
                        events
                            .publish("route.deleted", None, serde_json::to_value(&result)?)
                            .await;
                    }
                    send_result(&mut writer, request.id, &result).await?
                }
                Err(error) => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("route_rejected", error.to_string()),
                    )
                    .await?
                }
            }
        }
        Method::Snapshot => {
            let state = runtime_state.borrow().clone();
            match state {
                Some(state) => match state.live_snapshot().await {
                    Ok(status) => send_result(&mut writer, request.id, &status).await?,
                    Err(error) => {
                        send_error(
                            &mut writer,
                            request.id,
                            RpcError::new("snapshot_failed", error.to_string()),
                        )
                        .await?
                    }
                },
                None => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("runtime_unavailable", "data plane is not active"),
                    )
                    .await?
                }
            }
        }
        Method::Status => {
            let state = runtime_state.borrow().clone();
            match state {
                Some(state) => match state.live_snapshot().await {
                    Ok(status) => send_result(&mut writer, request.id, &status).await?,
                    Err(error) => {
                        send_error(
                            &mut writer,
                            request.id,
                            RpcError::new("status_unavailable", error.to_string()),
                        )
                        .await?
                    }
                },
                None => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("runtime_unavailable", "data plane is not active"),
                    )
                    .await?
                }
            }
        }
        Method::Peers => {
            let state = runtime_state.borrow().clone();
            match state {
                Some(state) => match state.live_snapshot().await {
                    Ok(status) => send_result(&mut writer, request.id, &status.peers).await?,
                    Err(error) => {
                        send_error(
                            &mut writer,
                            request.id,
                            RpcError::new("status_unavailable", error.to_string()),
                        )
                        .await?
                    }
                },
                None => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("runtime_unavailable", "data plane is not active"),
                    )
                    .await?
                }
            }
        }
        Method::Health => {
            let config = active_config.borrow().clone();
            let state = runtime_state.borrow().clone();
            match state {
                Some(state) => match state.live_snapshot().await {
                    Ok(status) => match ensure_healthy(&config, &status) {
                        Ok(()) => send_result(&mut writer, request.id, &status).await?,
                        Err(error) => {
                            send_error(
                                &mut writer,
                                request.id,
                                RpcError::new("unhealthy", error.to_string()),
                            )
                            .await?
                        }
                    },
                    Err(error) => {
                        send_error(
                            &mut writer,
                            request.id,
                            RpcError::new("status_unavailable", error.to_string()),
                        )
                        .await?
                    }
                },
                None => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("runtime_unavailable", "data plane is not active"),
                    )
                    .await?
                }
            }
        }
        Method::Ping {
            target,
            count,
            timeout_ms,
        } => {
            let timeout = Duration::from_millis(timeout_ms);
            if !(1..=trace::MAX_PING_COUNT).contains(&count)
                || timeout.is_zero()
                || timeout > MAX_TRACE_HOP_TIMEOUT
            {
                send_error(
                    &mut writer,
                    request.id,
                    RpcError::new(
                        "invalid_params",
                        format!(
                            "ping requires 1-{} probes and a timeout of 1-60000 ms",
                            trace::MAX_PING_COUNT
                        ),
                    ),
                )
                .await?;
                return Ok(());
            }
            let config = active_config.borrow().clone();
            let (sample_tx, mut sample_rx) = mpsc::channel(1);
            let ping_task = tokio::spawn(async move {
                trace::ping_streaming(&config, target, count, timeout, Some(sample_tx)).await
            });
            while let Some(sample) = sample_rx.recv().await {
                if let Err(error) = send_message(
                    &mut writer,
                    &ServerMessage::PingSample {
                        version: CONTROL_PROTOCOL_VERSION,
                        id: request.id,
                        sample,
                    },
                )
                .await
                {
                    ping_task.abort();
                    let _ = ping_task.await;
                    return Err(error);
                }
            }
            match ping_task.await.context("ping task panicked")? {
                Ok(result) => {
                    send_message(
                        &mut writer,
                        &ServerMessage::PingDone {
                            version: CONTROL_PROTOCOL_VERSION,
                            id: request.id,
                            result,
                        },
                    )
                    .await?
                }
                Err(error) => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("ping_failed", error.to_string()),
                    )
                    .await?
                }
            }
        }
        Method::Trace {
            target,
            max_hops,
            timeout_ms,
        } => {
            let timeout = Duration::from_millis(timeout_ms);
            if max_hops == 0 || timeout.is_zero() || timeout > MAX_TRACE_HOP_TIMEOUT {
                send_error(
                    &mut writer,
                    request.id,
                    RpcError::new(
                        "invalid_params",
                        "trace requires 1-255 hops and a per-hop timeout of 1-60000 ms",
                    ),
                )
                .await?;
                return Ok(());
            }
            let config = active_config.borrow().clone();
            let oam_events = runtime_state
                .borrow()
                .as_ref()
                .map(|state| state.subscribe_trace_events());
            let (hop_tx, mut hop_rx) = mpsc::channel(1);
            let trace_task = tokio::spawn(async move {
                trace::run_streaming_with_oam(
                    &config,
                    target,
                    max_hops,
                    timeout,
                    oam_events,
                    Some(hop_tx),
                )
                .await
            });
            while let Some(hop) = hop_rx.recv().await {
                send_message(
                    &mut writer,
                    &ServerMessage::TraceHop {
                        version: CONTROL_PROTOCOL_VERSION,
                        id: request.id,
                        hop,
                    },
                )
                .await?;
            }
            match trace_task.await.context("trace task panicked")? {
                Ok(result) => {
                    send_message(
                        &mut writer,
                        &ServerMessage::TraceDone {
                            version: CONTROL_PROTOCOL_VERSION,
                            id: request.id,
                            result,
                        },
                    )
                    .await?
                }
                Err(error) => {
                    send_error(
                        &mut writer,
                        request.id,
                        RpcError::new("trace_failed", error.to_string()),
                    )
                    .await?
                }
            }
        }
        Method::Reload => {
            if peer.uid != 0 && peer.uid != owner_uid {
                send_error(
                    &mut writer,
                    request.id,
                    RpcError::new(
                        "permission_denied",
                        "reload requires root or the daemon service user",
                    ),
                )
                .await?;
                return Ok(());
            }
            let (reply, response) = oneshot::channel();
            command_tx
                .send(DaemonCommand::Reload { reply })
                .await
                .map_err(|_| anyhow::anyhow!("daemon supervisor stopped"))?;
            match response.await.context("daemon dropped reload response")? {
                Ok(ack) => send_result(&mut writer, request.id, &ack).await?,
                Err(error) => send_error(&mut writer, request.id, error).await?,
            }
        }
    }
    Ok(())
}

fn method_name(method: &Method) -> &'static str {
    match method {
        Method::GetCapabilities => "get_capabilities",
        Method::GetSnapshot => "get_snapshot",
        Method::WatchEvents { .. } => "watch_events",
        Method::ListRoutes => "list_routes",
        Method::ApplyRoutes { .. } => "apply_routes",
        Method::DeleteRoutes { .. } => "delete_routes",
        Method::Snapshot => "snapshot",
        Method::Status => "status",
        Method::Peers => "peers",
        Method::Health => "health",
        Method::Ping { .. } => "ping",
        Method::Trace { .. } => "trace",
        Method::Reload => "reload",
    }
}

fn capabilities() -> CapabilitySet {
    CapabilitySet {
        api_version: CONTROL_PROTOCOL_VERSION,
        minimum_api_version: CONTROL_PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").into(),
        capabilities: vec![
            capability("snapshot", 1, false, false),
            capability("events", 1, true, false),
            capability("desired_routes", 1, false, true),
            capability("diagnostics", 1, true, false),
        ],
        limits: ApiLimits {
            maximum_request_bytes: MAX_REQUEST_BYTES,
            maximum_response_bytes: MAX_RESPONSE_BYTES,
            event_history: EVENT_HISTORY_LIMIT,
            maximum_route_ttl_seconds: extensions::MAX_ROUTE_TTL_SECONDS,
        },
    }
}

fn capability(name: &str, version: u16, streaming: bool, mutable: bool) -> Capability {
    Capability {
        name: name.into(),
        version,
        streaming,
        mutable,
    }
}

fn can_mutate(peer: PeerIdentity, owner_uid: u32) -> bool {
    peer.uid == 0 || peer.uid == owner_uid
}

async fn load_extension_routes(config: &Config) -> Result<Vec<ironet_extension_sdk::DesiredRoute>> {
    Ok(
        ExtensionState::load(&extensions::state_path(&config.identity_file))
            .await?
            .list(extensions::now_unix()),
    )
}

async fn mutate_extension_routes(
    config: &Config,
    dry_run: bool,
    mutate: impl FnOnce(&ExtensionState, u64) -> Result<extensions::Mutation>,
    command_tx: &mpsc::Sender<DaemonCommand>,
) -> Result<RouteMutationResult> {
    let path = extensions::state_path(&config.identity_file);
    let previous = ExtensionState::load(&path).await?;
    let mutation = mutate(&previous, extensions::now_unix())?;
    let result = mutation.result;
    validate_extension_candidate(config, &mutation.state).await?;
    if dry_run || !mutation.persist {
        return Ok(result);
    }
    mutation.state.write(&path)?;
    if !mutation.reload {
        return Ok(result);
    }
    let (reply, response) = oneshot::channel();
    command_tx
        .send(DaemonCommand::Reload { reply })
        .await
        .map_err(|_| anyhow::anyhow!("daemon supervisor stopped"))?;
    if let Err(error) = response.await.context("daemon dropped reload response")? {
        previous
            .write(&path)
            .context("failed restoring extension desired state")?;
        bail!(
            "daemon {}: {}; restored previous desired state",
            error.code,
            error.message
        );
    }
    Ok(result)
}

async fn validate_extension_candidate(config: &Config, state: &ExtensionState) -> Result<()> {
    crate::routes::RouteSources::load_with_extension_candidate(&config.identity_file, state.clone())
        .await?
        .validate_candidate(config)
}

pub fn ensure_healthy(config: &Config, status: &RuntimeStatus) -> Result<()> {
    let _ = config;
    ensure!(status.ready, "runtime is not ready");
    Ok(())
}

async fn send_result<T: Serialize>(writer: &mut OwnedWriteHalf, id: u64, result: &T) -> Result<()> {
    send_message(
        writer,
        &ServerMessage::Result {
            version: CONTROL_PROTOCOL_VERSION,
            id,
            result: serde_json::to_value(result)?,
        },
    )
    .await
}

async fn send_error(writer: &mut OwnedWriteHalf, id: u64, error: RpcError) -> Result<()> {
    send_message(
        writer,
        &ServerMessage::Error {
            version: CONTROL_PROTOCOL_VERSION,
            id,
            error,
        },
    )
    .await
}

async fn send_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ServerMessage,
) -> Result<()> {
    json_line::write(writer, message, MAX_RESPONSE_BYTES).await
}

fn request_parameters(method: &Method) -> Result<serde_json::Value> {
    let mut parameters = serde_json::to_value(method).context("failed encoding control request")?;
    let object = parameters
        .as_object_mut()
        .context("control method did not encode as an object")?;
    object.remove("method");
    Ok(parameters)
}

async fn connect(path: &Path, method: Method) -> Result<ControlResponseStream> {
    let parameters = request_parameters(&method)?;
    Ok(ControlClient::new(path)
        .request_stream(method_name(&method), parameters)
        .await?)
}

async fn request_result<T: DeserializeOwned>(path: &Path, method: Method) -> Result<T> {
    let parameters = request_parameters(&method)?;
    Ok(ControlClient::new(path)
        .request_raw(method_name(&method), parameters)
        .await?)
}

pub async fn status(path: &Path) -> Result<RuntimeStatus> {
    request_result(path, Method::Status).await
}

pub async fn snapshot(path: &Path) -> Result<RuntimeStatus> {
    request_result(path, Method::Snapshot).await
}

pub async fn peers(path: &Path) -> Result<Vec<PeerStatus>> {
    request_result(path, Method::Peers).await
}

pub async fn health(path: &Path) -> Result<RuntimeStatus> {
    request_result(path, Method::Health).await
}

pub async fn reload(path: &Path) -> Result<ReloadAck> {
    request_result(path, Method::Reload).await
}

pub async fn ping(
    path: &Path,
    target: IpAddr,
    count: u16,
    timeout: Duration,
) -> Result<PingResult> {
    ping_with(path, target, count, timeout, |_| Ok(())).await
}

pub async fn ping_with<F>(
    path: &Path,
    target: IpAddr,
    count: u16,
    timeout: Duration,
    mut on_sample: F,
) -> Result<PingResult>
where
    F: FnMut(&PingSample) -> Result<()>,
{
    ensure!(
        (1..=trace::MAX_PING_COUNT).contains(&count),
        "ping count must be between 1 and {}",
        trace::MAX_PING_COUNT
    );
    ensure!(
        !timeout.is_zero() && timeout <= MAX_TRACE_HOP_TIMEOUT,
        "ping timeout must be between 1 ms and 60 s"
    );
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let mut stream = connect(
        path,
        Method::Ping {
            target,
            count,
            timeout_ms,
        },
    )
    .await?;
    let mut streamed_samples = Vec::new();
    loop {
        let message: ServerMessage = serde_json::from_value(stream.next_frame().await?)
            .context("failed parsing daemon ping event")?;
        match message {
            ServerMessage::PingSample { sample, .. } => {
                on_sample(&sample)?;
                streamed_samples.push(sample);
            }
            ServerMessage::PingDone { result, .. } => {
                ensure!(
                    streamed_samples == result.samples,
                    "daemon ping stream disagrees with final result"
                );
                return Ok(result);
            }
            ServerMessage::Error { error, .. } => {
                bail!("daemon {}: {}", error.code, error.message);
            }
            ServerMessage::Result { .. }
            | ServerMessage::TraceHop { .. }
            | ServerMessage::TraceDone { .. }
            | ServerMessage::ExtensionEvent { .. } => {
                bail!("daemon returned a non-ping result")
            }
        }
    }
}

pub async fn trace(
    path: &Path,
    target: IpAddr,
    max_hops: u8,
    timeout: Duration,
) -> Result<TraceResult> {
    trace_with(path, target, max_hops, timeout, |_| Ok(())).await
}

pub async fn trace_with<F>(
    path: &Path,
    target: IpAddr,
    max_hops: u8,
    timeout: Duration,
    mut on_hop: F,
) -> Result<TraceResult>
where
    F: FnMut(&TraceHop) -> Result<()>,
{
    ensure!(max_hops > 0, "trace max hops must be greater than zero");
    ensure!(
        !timeout.is_zero() && timeout <= MAX_TRACE_HOP_TIMEOUT,
        "trace timeout must be between 1 ms and 60 s"
    );
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let mut stream = connect(
        path,
        Method::Trace {
            target,
            max_hops,
            timeout_ms,
        },
    )
    .await?;
    let mut streamed_hops = Vec::new();
    loop {
        let message: ServerMessage = serde_json::from_value(stream.next_frame().await?)
            .context("failed parsing daemon trace event")?;
        match message {
            ServerMessage::TraceHop { hop, .. } => {
                on_hop(&hop)?;
                streamed_hops.push(hop);
            }
            ServerMessage::TraceDone { result, .. } => {
                ensure!(
                    streamed_hops == result.hops,
                    "daemon trace stream disagrees with final result"
                );
                return Ok(result);
            }
            ServerMessage::Error { error, .. } => {
                bail!("daemon {}: {}", error.code, error.message);
            }
            ServerMessage::Result { .. }
            | ServerMessage::PingSample { .. }
            | ServerMessage::PingDone { .. }
            | ServerMessage::ExtensionEvent { .. } => {
                bail!("daemon returned a non-trace result")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2_runtime::{V2RuntimeConfig, V2RuntimeState};
    use iroh::SecretKey;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncWriteExt, BufReader};

    fn test_config(directory: &Path) -> Config {
        let _ = directory;
        toml::from_str(include_str!("../config/example.toml")).unwrap()
    }

    #[tokio::test]
    async fn bounded_line_rejects_oversized_messages() {
        let data = vec![b'x'; 9];
        let mut reader = BufReader::new(data.as_slice());
        let error = json_line::read_bounded_line(&mut reader, 8)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 8 bytes"));
    }

    #[test]
    fn request_is_versioned_and_method_tagged() {
        let request = Request {
            version: CONTROL_PROTOCOL_VERSION,
            id: 7,
            method: Method::Status,
        };
        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["version"], CONTROL_PROTOCOL_VERSION);
        assert_eq!(json["id"], 7);
        assert_eq!(json["method"], "status");
    }

    #[test]
    fn live_snapshot_request_is_versioned_and_method_tagged() {
        let request = Request {
            version: CONTROL_PROTOCOL_VERSION,
            id: 8,
            method: Method::Snapshot,
        };
        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["version"], CONTROL_PROTOCOL_VERSION);
        assert_eq!(json["id"], 8);
        assert_eq!(json["method"], "snapshot");
    }

    #[tokio::test]
    async fn extension_candidate_validation_composes_operator_and_candidate_sources() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = test_config(directory.path());
        config.identity_file = directory.path().join("identity.key");
        config.route_origins.clear();

        let operator = SecretKey::from_bytes(&[31; 32]).public();
        crate::routes::RouteRegistry::parse_lines(&format!("{operator} 10.40.0.0/24\n"))
            .unwrap()
            .write(&config.route_registry_path())
            .unwrap();

        let extension = ExtensionState::new()
            .apply(
                &ApplyRoutesRequest {
                    routes: vec![ironet_extension_sdk::RouteApply {
                        api_version: CONTROL_PROTOCOL_VERSION,
                        name: "office".into(),
                        owner: "example.com/ipam".into(),
                        revision: 1,
                        ttl_seconds: None,
                        spec: ironet_extension_sdk::DesiredRouteSpec {
                            endpoint_id: SecretKey::from_bytes(&[32; 32]).public().to_string(),
                            prefixes: vec!["10.40.0.128/25".into()],
                        },
                    }],
                    dry_run: false,
                    idempotency_key: "candidate-composition".into(),
                },
                100,
            )
            .unwrap()
            .state;

        let error = validate_extension_candidate(&config, &extension)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("overlaps"), "{error}");
    }

    #[test]
    fn ping_request_has_bounded_probe_parameters() {
        let request = Request {
            version: CONTROL_PROTOCOL_VERSION,
            id: 8,
            method: Method::Ping {
                target: "21.0.0.2".parse().unwrap(),
                count: 4,
                timeout_ms: 1_000,
            },
        };
        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["method"], "ping");
        assert_eq!(json["target"], "21.0.0.2");
        assert_eq!(json["count"], 4);
        assert_eq!(json["timeout_ms"], 1_000);
    }

    #[tokio::test]
    async fn bind_never_replaces_a_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        std::fs::write(&socket, b"keep").unwrap();

        let error = bind(&socket).await.unwrap_err();
        assert!(error.to_string().contains("refusing to replace non-socket"));
        assert_eq!(std::fs::read(&socket).unwrap(), b"keep");
    }

    #[tokio::test]
    async fn socket_is_private_and_status_errors_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o660
        );
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(test_config(directory.path()));
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            watch::channel(None).1,
            Arc::new(EventLog::default()),
        ));

        let error = status(&socket).await.unwrap_err();
        assert!(error.to_string().contains("daemon runtime_unavailable"));
        server.abort();
    }

    #[tokio::test]
    async fn malformed_and_unknown_requests_return_structured_errors() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(test_config(directory.path()));
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            watch::channel(None).1,
            Arc::new(EventLog::default()),
        ));

        let requests: [&[u8]; 2] = [
            b"{not-json}\n",
            b"{\"version\":1,\"id\":9,\"method\":\"unknown\"}\n",
        ];
        for request in requests {
            let mut stream = UnixStream::connect(&socket).await.unwrap();
            stream.write_all(request).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reader = BufReader::new(stream);
            let line = json_line::read_bounded_line(&mut reader, MAX_RESPONSE_BYTES)
                .await
                .unwrap();
            match serde_json::from_slice::<ServerMessage>(&line).unwrap() {
                ServerMessage::Error { error, .. } => {
                    assert_eq!(error.code, "invalid_request");
                }
                message => panic!("expected structured error, got {message:?}"),
            }
        }
        server.abort();
    }

    #[tokio::test]
    async fn unsupported_version_and_invalid_ping_params_are_rejected_by_server() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(test_config(directory.path()));
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            watch::channel(None).1,
            Arc::new(EventLog::default()),
        ));

        let mut stream = UnixStream::connect(&socket).await.unwrap();
        stream
            .write_all(b"{\"version\":99,\"id\":10,\"method\":\"status\"}\n")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut reader = BufReader::new(stream);
        let line = json_line::read_bounded_line(&mut reader, MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        match serde_json::from_slice::<ServerMessage>(&line).unwrap() {
            ServerMessage::Error { id, error, .. } => {
                assert_eq!(id, 10);
                assert_eq!(error.code, "unsupported_version");
            }
            message => panic!("expected version error, got {message:?}"),
        }

        let error = request_result::<PingResult>(
            &socket,
            Method::Ping {
                target: "21.0.0.1".parse().unwrap(),
                count: 0,
                timeout_ms: 1_000,
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("daemon invalid_params"));
        server.abort();
    }

    #[tokio::test]
    async fn client_rejects_ping_bounds_before_connecting() {
        let missing = Path::new("/definitely/missing/control.sock");
        let target = "21.0.0.1".parse().unwrap();
        let count_error = ping(missing, target, 0, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(count_error.to_string().contains("count must be between"));
        let timeout_error = ping(missing, target, 1, Duration::from_secs(61))
            .await
            .unwrap_err();
        assert!(
            timeout_error
                .to_string()
                .contains("timeout must be between")
        );
    }

    #[tokio::test]
    async fn peers_are_projected_from_runtime_status() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        let config = test_config(directory.path());
        let endpoint_id = SecretKey::from_bytes(&[12; 32]).public();
        let runtime_config = V2RuntimeConfig::from_product_config(&config).unwrap();
        let runtime_state = Arc::new(V2RuntimeState::new(&runtime_config, endpoint_id));
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(config);
        let (_state_tx, state_rx) = watch::channel(Some(runtime_state));
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            state_rx,
            Arc::new(EventLog::default()),
        ));

        assert!(peers(&socket).await.unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn live_snapshot_reads_v2_runtime_state() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        let config = test_config(directory.path());
        let endpoint_id = SecretKey::from_bytes(&[11; 32]).public();
        let runtime_config = V2RuntimeConfig::from_product_config(&config).unwrap();
        let runtime_state = Arc::new(V2RuntimeState::new(&runtime_config, endpoint_id));
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(config);
        let (_state_tx, state_rx) = watch::channel(Some(runtime_state));
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            state_rx,
            Arc::new(EventLog::default()),
        ));

        let status = snapshot(&socket).await.unwrap();
        assert_eq!(status.endpoint_id, endpoint_id.to_string());
        server.abort();
    }

    #[tokio::test]
    async fn overlay_ping_round_trips_through_control_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        let config = test_config(directory.path());
        let target = config.node_addresses[0].addr();
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(config);
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            watch::channel(None).1,
            Arc::new(EventLog::default()),
        ));

        let mut sequences = Vec::new();
        let result = ping_with(&socket, target, 2, Duration::from_millis(10), |sample| {
            sequences.push(sample.sequence);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(result.transmitted, 2);
        assert_eq!(result.received, 2);
        assert_eq!(result.loss_ppm, 0);
        assert_eq!(sequences, [1, 2]);
        server.abort();
    }

    #[tokio::test]
    async fn connection_limit_applies_backpressure_and_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(test_config(directory.path()));
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            watch::channel(None).1,
            Arc::new(EventLog::default()),
        ));

        let mut idle = Vec::with_capacity(MAX_CONTROL_CONNECTIONS);
        for _ in 0..MAX_CONTROL_CONNECTIONS {
            let mut stream = UnixStream::connect(&socket).await.unwrap();
            stream.write_all(b"{").await.unwrap();
            idle.push(stream);
        }
        time::sleep(Duration::from_millis(200)).await;

        let client_socket = socket.clone();
        let mut waiting = tokio::spawn(async move { status(&client_socket).await });
        assert!(
            time::timeout(Duration::from_millis(200), &mut waiting)
                .await
                .is_err(),
            "the 65th request should wait for a connection slot"
        );
        drop(idle.pop());
        let error = time::timeout(Duration::from_secs(2), waiting)
            .await
            .expect("request should resume after a slot is released")
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("runtime_unavailable"));
        drop(idle);
        server.abort();
    }

    #[tokio::test]
    async fn reload_round_trips_through_supervisor_channel() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        let (command_tx, mut command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(test_config(directory.path()));
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            watch::channel(None).1,
            Arc::new(EventLog::default()),
        ));
        let client_socket = socket.clone();
        let client = tokio::spawn(async move { reload(&client_socket).await });

        let Some(DaemonCommand::Reload { reply }) = command_rx.recv().await else {
            panic!("expected reload command");
        };
        reply
            .send(Ok(ReloadAck {
                generation: 2,
                endpoint_id: "endpoint".into(),
            }))
            .unwrap();
        let ack = client.await.unwrap().unwrap();
        assert_eq!(ack.generation, 2);
        assert_eq!(ack.endpoint_id, "endpoint");
        server.abort();
    }

    #[tokio::test]
    async fn extension_capabilities_and_event_replay_are_versioned() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = bind(&socket).await.unwrap();
        let (command_tx, _command_rx) = mpsc::channel(1);
        let (_active_tx, active_rx) = watch::channel(test_config(directory.path()));
        let events = Arc::new(EventLog::default());
        events
            .publish("daemon.ready", None, serde_json::json!({"generation": 1}))
            .await;
        let server = tokio::spawn(serve(
            listener,
            socket.clone(),
            active_rx,
            command_tx,
            watch::channel(None).1,
            events,
        ));

        let capabilities = ironet_extension_sdk::Client::new(&socket)
            .capabilities()
            .await
            .unwrap();
        assert_eq!(capabilities.api_version, CONTROL_PROTOCOL_VERSION);
        assert!(
            capabilities
                .capabilities
                .iter()
                .any(|capability| capability.name == "events" && capability.streaming)
        );

        let mut stream = connect(
            &socket,
            Method::WatchEvents {
                after_cursor: Some(0),
            },
        )
        .await
        .unwrap();
        let id = stream.request_id();
        let ack: ServerMessage =
            serde_json::from_value(stream.next_frame().await.unwrap()).unwrap();
        assert!(matches!(ack, ServerMessage::Result { id: response, .. } if response == id));
        let event: ServerMessage =
            serde_json::from_value(stream.next_frame().await.unwrap()).unwrap();
        assert!(matches!(
            event,
            ServerMessage::ExtensionEvent { extension_event, .. }
                if extension_event.kind == "daemon.ready" && extension_event.cursor == 1
        ));
        server.abort();
    }

    #[tokio::test]
    async fn event_history_requires_snapshot_after_cursor_expiry() {
        let events = EventLog::default();
        for sequence in 0..=EVENT_HISTORY_LIMIT {
            events
                .publish("test", None, serde_json::json!({"sequence": sequence}))
                .await;
        }
        let error = events.after(0).await.unwrap_err();
        assert_eq!(error.code, "cursor_expired");
        assert_eq!(events.bounds().await.oldest_cursor, 2);
    }
}
