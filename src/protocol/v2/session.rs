use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use iroh::{
    EndpointId,
    endpoint::{Connection, Side},
};

use super::MAJOR;

pub const MAGIC: &[u8; 4] = b"ISV2";
pub const MAX_NETWORK_ID_BYTES: usize = 128;
pub const MAX_CONTROL_BYTES: u32 = 1024 * 1024;
pub const MAX_TRAIN_BYTES: u32 = 64 * 1024;
pub const MAX_RECORD_BYTES: u32 = u16::MAX as u32;
pub const MAX_CELLS_PER_TRAIN: u16 = 256;
pub const MAX_ACTIVE_TRAINS: u16 = 4096;

const FIXED_HEADER_LEN: usize = 200;
const RESERVED: u8 = 0;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HANDSHAKE_RECORD_BYTES: usize = FIXED_HEADER_LEN + MAX_NETWORK_ID_BYTES;
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Ironet-V2-Session";
const READY_MAGIC: &[u8; 4] = b"IRV2";
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub mod capability {
    pub const PACKET_TRAIN: u64 = 1 << 0;
    pub const FEC_STRIPES: u64 = 1 << 1;
    pub const GSO_METADATA: u64 = 1 << 2;
    pub const ROUTE_LABELS: u64 = 1 << 3;
    pub const LIVE_MEDIA: u64 = 1 << 4;
    pub const BULK_QOS: u64 = 1 << 5;
    pub const REPAIR_STREAM: u64 = 1 << 6;

    pub const REQUIRED: u64 = PACKET_TRAIN | ROUTE_LABELS | BULK_QOS;
    pub const KNOWN: u64 = PACKET_TRAIN
        | FEC_STRIPES
        | GSO_METADATA
        | ROUTE_LABELS
        | LIVE_MEDIA
        | BULK_QOS
        | REPAIR_STREAM;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionRole {
    Data = 1,
    Probe = 2,
    AdditionalLane = 3,
}

impl ConnectionRole {
    fn from_wire(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::Data,
            2 => Self::Probe,
            3 => Self::AdditionalLane,
            _ => anyhow::bail!("unknown V2 connection role {value}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLimitsV2 {
    pub max_datagram_size: u16,
    pub max_control_size: u32,
    pub max_train_size: u32,
    pub max_record_size: u32,
    pub max_cells_per_train: u16,
    pub max_active_trains: u16,
}

impl WireLimitsV2 {
    pub fn validate(self) -> Result<()> {
        ensure!(
            self.max_datagram_size as usize > crate::protocol::v2::cell::HEADER_LEN,
            "V2 datagram limit is too small"
        );
        ensure!(
            (1..=MAX_CONTROL_BYTES).contains(&self.max_control_size),
            "V2 control limit is invalid"
        );
        ensure!(
            (self.max_datagram_size as u32..=MAX_TRAIN_BYTES).contains(&self.max_train_size),
            "V2 train limit is invalid"
        );
        ensure!(
            (1..=MAX_RECORD_BYTES).contains(&self.max_record_size),
            "V2 record limit is invalid"
        );
        ensure!(
            (1..=MAX_CELLS_PER_TRAIN).contains(&self.max_cells_per_train),
            "V2 cells-per-train limit is invalid"
        );
        ensure!(
            (1..=MAX_ACTIVE_TRAINS).contains(&self.max_active_trains),
            "V2 active-train limit is invalid"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHelloV2 {
    pub role: ConnectionRole,
    pub capabilities: u64,
    pub network_id: String,
    pub local_id: EndpointId,
    pub expected_remote_id: EndpointId,
    pub limits: WireLimitsV2,
    pub cover_profile_id: u32,
    pub nonce: [u8; 32],
    /// Hash derived from a QUIC TLS exporter and the connection context.
    pub exporter_binding: [u8; 32],
    /// Network membership proof over the complete hello transcript.
    pub membership_proof: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SessionPolicyV2 {
    pub network_id: String,
    pub local_id: EndpointId,
    pub remote_id: EndpointId,
    pub role: ConnectionRole,
    pub expected_remote_role: Option<ConnectionRole>,
    pub capabilities: u64,
    pub limits: WireLimitsV2,
    pub cover_profile_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedSessionV2 {
    pub local_role: ConnectionRole,
    pub remote_role: ConnectionRole,
    pub capabilities: u64,
    pub limits: WireLimitsV2,
    pub cover_profile_id: u32,
    pub session_epoch: u32,
}

impl SessionHelloV2 {
    pub fn encode(&self) -> Result<Bytes> {
        self.validate()?;
        Ok(self.encode_wire())
    }

    fn encode_wire(&self) -> Bytes {
        let network = self.network_id.as_bytes();
        let mut out = BytesMut::with_capacity(FIXED_HEADER_LEN + network.len());
        out.extend_from_slice(MAGIC);
        out.put_u16(MAJOR);
        out.put_u8(self.role as u8);
        out.put_u8(RESERVED);
        out.put_u64(self.capabilities);
        out.put_u16(network.len() as u16);
        out.put_u16(self.limits.max_datagram_size);
        out.put_u32(self.limits.max_control_size);
        out.put_u32(self.limits.max_train_size);
        out.put_u32(self.limits.max_record_size);
        out.put_u16(self.limits.max_cells_per_train);
        out.put_u16(self.limits.max_active_trains);
        out.put_u32(self.cover_profile_id);
        out.extend_from_slice(self.local_id.as_bytes());
        out.extend_from_slice(self.expected_remote_id.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.exporter_binding);
        out.extend_from_slice(&self.membership_proof);
        debug_assert_eq!(out.len(), FIXED_HEADER_LEN);
        out.extend_from_slice(network);
        out.freeze()
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(
            (FIXED_HEADER_LEN..=FIXED_HEADER_LEN + MAX_NETWORK_ID_BYTES).contains(&bytes.len()),
            "invalid V2 session hello length"
        );
        ensure!(&bytes[..4] == MAGIC, "invalid V2 session hello magic");
        ensure!(
            u16::from_be_bytes(bytes[4..6].try_into().unwrap()) == MAJOR,
            "unsupported V2 session major"
        );
        let role = ConnectionRole::from_wire(bytes[6])?;
        ensure!(bytes[7] == RESERVED, "unsupported V2 session flags");
        let capabilities = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let network_len = usize::from(u16::from_be_bytes(bytes[16..18].try_into().unwrap()));
        ensure!(
            network_len <= MAX_NETWORK_ID_BYTES && FIXED_HEADER_LEN + network_len == bytes.len(),
            "invalid V2 network id length"
        );
        let limits = WireLimitsV2 {
            max_datagram_size: u16::from_be_bytes(bytes[18..20].try_into().unwrap()),
            max_control_size: u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
            max_train_size: u32::from_be_bytes(bytes[24..28].try_into().unwrap()),
            max_record_size: u32::from_be_bytes(bytes[28..32].try_into().unwrap()),
            max_cells_per_train: u16::from_be_bytes(bytes[32..34].try_into().unwrap()),
            max_active_trains: u16::from_be_bytes(bytes[34..36].try_into().unwrap()),
        };
        let cover_profile_id = u32::from_be_bytes(bytes[36..40].try_into().unwrap());
        let local_id = endpoint_id(&bytes[40..72])?;
        let expected_remote_id = endpoint_id(&bytes[72..104])?;
        let mut nonce = [0_u8; 32];
        nonce.copy_from_slice(&bytes[104..136]);
        let mut exporter_binding = [0_u8; 32];
        exporter_binding.copy_from_slice(&bytes[136..168]);
        let mut membership_proof = [0_u8; 32];
        membership_proof.copy_from_slice(&bytes[168..200]);
        let network_id = std::str::from_utf8(&bytes[FIXED_HEADER_LEN..])
            .map_err(|_| anyhow::anyhow!("V2 network id is not UTF-8"))?
            .to_owned();
        let hello = Self {
            role,
            capabilities,
            network_id,
            local_id,
            expected_remote_id,
            limits,
            cover_profile_id,
            nonce,
            exporter_binding,
            membership_proof,
        };
        hello.validate()?;
        Ok(hello)
    }

    pub fn validate(&self) -> Result<()> {
        let network = self.network_id.as_bytes();
        ensure!(
            !network.is_empty() && network.len() <= MAX_NETWORK_ID_BYTES,
            "V2 network id length is invalid"
        );
        ensure!(!network.contains(&0), "V2 network id contains NUL");
        ensure!(
            self.local_id != self.expected_remote_id,
            "V2 session cannot target the local endpoint"
        );
        ensure!(
            self.capabilities & !capability::KNOWN == 0,
            "V2 hello contains unknown capabilities"
        );
        ensure!(
            self.capabilities & capability::REQUIRED == capability::REQUIRED,
            "V2 hello omits required capabilities"
        );
        ensure!(self.nonce != [0; 32], "V2 session nonce is zero");
        ensure!(
            self.exporter_binding != [0; 32],
            "V2 exporter binding is zero"
        );
        ensure!(
            self.membership_proof != [0; 32],
            "V2 membership proof is zero"
        );
        self.limits.validate()
    }
}

pub async fn negotiate_connection_v2(
    connection: &Connection,
    policy: &SessionPolicyV2,
) -> Result<NegotiatedSessionV2> {
    validate_policy(connection, policy)?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        match connection.side() {
            Side::Client => client(connection, policy).await,
            Side::Server => server(connection, policy).await,
        }
    })
    .await
    .context("V2 session handshake timed out")?
}

async fn client(connection: &Connection, policy: &SessionPolicyV2) -> Result<NegotiatedSessionV2> {
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .context("opening V2 session control stream")?;
    let hello = make_hello(connection, policy)?;
    let client_bytes = hello.encode()?;
    write_record(&mut send, &client_bytes).await?;
    let server_bytes = read_record(&mut receive).await?;
    let remote = SessionHelloV2::decode(server_bytes.clone())?;
    validate_remote_hello(connection, policy, &remote)?;
    let transcript = transcript(&client_bytes, &server_bytes);
    write_ready(&mut send, transcript).await?;
    send.finish()
        .context("finishing V2 session control stream")?;
    Ok(negotiate(policy, &remote, transcript))
}

async fn server(connection: &Connection, policy: &SessionPolicyV2) -> Result<NegotiatedSessionV2> {
    let (mut send, mut receive) = connection
        .accept_bi()
        .await
        .context("accepting V2 session control stream")?;
    let client_bytes = read_record(&mut receive).await?;
    let remote = SessionHelloV2::decode(client_bytes.clone())?;
    validate_remote_hello(connection, policy, &remote)?;
    let hello = make_hello(connection, policy)?;
    let server_bytes = hello.encode()?;
    write_record(&mut send, &server_bytes).await?;
    let transcript = transcript(&client_bytes, &server_bytes);
    read_ready(&mut receive, transcript).await?;
    send.finish().context("finishing V2 session response")?;
    Ok(negotiate(policy, &remote, transcript))
}

fn validate_policy(connection: &Connection, policy: &SessionPolicyV2) -> Result<()> {
    ensure!(
        connection.remote_id() == policy.remote_id,
        "V2 session peer identity mismatch"
    );
    ensure!(
        connection.side() == Side::Client || connection.side() == Side::Server,
        "invalid V2 QUIC side"
    );
    ensure!(
        !policy.network_id.is_empty() && policy.network_id.len() <= MAX_NETWORK_ID_BYTES,
        "invalid V2 policy network ID"
    );
    ensure!(
        policy.capabilities & !capability::KNOWN == 0
            && policy.capabilities & capability::REQUIRED == capability::REQUIRED,
        "invalid V2 policy capabilities"
    );
    policy.limits.validate()
}

fn make_hello(connection: &Connection, policy: &SessionPolicyV2) -> Result<SessionHelloV2> {
    let mut hello = SessionHelloV2 {
        role: policy.role,
        capabilities: policy.capabilities,
        network_id: policy.network_id.clone(),
        local_id: policy.local_id,
        expected_remote_id: policy.remote_id,
        limits: policy.limits,
        cover_profile_id: policy.cover_profile_id,
        nonce: nonce(policy.local_id, policy.remote_id),
        exporter_binding: [0; 32],
        membership_proof: [0; 32],
    };
    hello.exporter_binding = exporter_binding(connection, &hello)?;
    hello.membership_proof = membership_proof(&policy.network_id, &hello);
    hello.validate()?;
    Ok(hello)
}

fn validate_remote_hello(
    connection: &Connection,
    policy: &SessionPolicyV2,
    hello: &SessionHelloV2,
) -> Result<()> {
    hello.validate()?;
    ensure!(hello.network_id == policy.network_id, "V2 network mismatch");
    ensure!(
        hello.local_id == policy.remote_id && hello.expected_remote_id == policy.local_id,
        "V2 hello identity mismatch"
    );
    if let Some(expected) = policy.expected_remote_role {
        ensure!(hello.role == expected, "V2 connection role mismatch");
    }
    ensure!(
        hello.cover_profile_id == policy.cover_profile_id,
        "V2 cover profile mismatch"
    );
    ensure!(
        constant_time_eq(
            &hello.exporter_binding,
            &exporter_binding(connection, hello)?
        ),
        "V2 hello is not bound to this QUIC TLS session"
    );
    ensure!(
        constant_time_eq(
            &hello.membership_proof,
            &membership_proof(&policy.network_id, hello)
        ),
        "invalid V2 network membership proof"
    );
    let negotiated = policy.capabilities & hello.capabilities;
    ensure!(
        negotiated & capability::REQUIRED == capability::REQUIRED,
        "V2 peer has no compatible required capability set"
    );
    Ok(())
}

fn negotiate(
    policy: &SessionPolicyV2,
    remote: &SessionHelloV2,
    transcript: [u8; 32],
) -> NegotiatedSessionV2 {
    let mut session_epoch = u32::from_be_bytes(transcript[..4].try_into().unwrap());
    if session_epoch == 0 {
        session_epoch = 1;
    }
    NegotiatedSessionV2 {
        local_role: policy.role,
        remote_role: remote.role,
        capabilities: policy.capabilities & remote.capabilities,
        limits: WireLimitsV2 {
            max_datagram_size: policy
                .limits
                .max_datagram_size
                .min(remote.limits.max_datagram_size),
            max_control_size: policy
                .limits
                .max_control_size
                .min(remote.limits.max_control_size),
            max_train_size: policy
                .limits
                .max_train_size
                .min(remote.limits.max_train_size),
            max_record_size: policy
                .limits
                .max_record_size
                .min(remote.limits.max_record_size),
            max_cells_per_train: policy
                .limits
                .max_cells_per_train
                .min(remote.limits.max_cells_per_train),
            max_active_trains: policy
                .limits
                .max_active_trains
                .min(remote.limits.max_active_trains),
        },
        cover_profile_id: policy.cover_profile_id,
        session_epoch,
    }
}

fn exporter_binding(connection: &Connection, hello: &SessionHelloV2) -> Result<[u8; 32]> {
    let mut unsigned = hello.clone();
    unsigned.exporter_binding = [0; 32];
    unsigned.membership_proof = [0; 32];
    let context = unsigned.encode_wire();
    let mut output = [0_u8; 32];
    connection
        .export_keying_material(&mut output, EXPORTER_LABEL, &context)
        .map_err(|_| anyhow::anyhow!("deriving V2 QUIC exporter binding failed"))?;
    Ok(output)
}

fn membership_proof(network_secret: &str, hello: &SessionHelloV2) -> [u8; 32] {
    let key = *blake3::hash(network_secret.as_bytes()).as_bytes();
    let mut unsigned = hello.clone();
    unsigned.membership_proof = [0; 32];
    let bytes = unsigned.encode_wire();
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(b"ironet-v2-membership");
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

fn transcript(client: &[u8], server: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v2-session-transcript");
    hasher.update(&(client.len() as u64).to_be_bytes());
    hasher.update(client);
    hasher.update(&(server.len() as u64).to_be_bytes());
    hasher.update(server);
    *hasher.finalize().as_bytes()
}

fn nonce(local: EndpointId, remote: EndpointId) -> [u8; 32] {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v2-nonce");
    hasher.update(local.as_bytes());
    hasher.update(remote.as_bytes());
    hasher.update(&counter.to_be_bytes());
    hasher.update(&now.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

async fn write_record(send: &mut iroh::endpoint::SendStream, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_HANDSHAKE_RECORD_BYTES,
        "V2 handshake record exceeds hard limit"
    );
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

async fn read_record(receive: &mut iroh::endpoint::RecvStream) -> Result<Bytes> {
    let mut length = [0_u8; 4];
    receive.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        (FIXED_HEADER_LEN..=MAX_HANDSHAKE_RECORD_BYTES).contains(&length),
        "invalid V2 handshake record length"
    );
    let mut bytes = BytesMut::zeroed(length);
    receive.read_exact(&mut bytes).await?;
    Ok(bytes.freeze())
}

async fn write_ready(send: &mut iroh::endpoint::SendStream, transcript: [u8; 32]) -> Result<()> {
    let mut ready = [0_u8; 36];
    ready[..4].copy_from_slice(READY_MAGIC);
    ready[4..].copy_from_slice(&transcript);
    send.write_all(&ready).await?;
    Ok(())
}

async fn read_ready(
    receive: &mut iroh::endpoint::RecvStream,
    expected_transcript: [u8; 32],
) -> Result<()> {
    let mut ready = [0_u8; 36];
    receive.read_exact(&mut ready).await?;
    ensure!(&ready[..4] == READY_MAGIC, "invalid V2 ready marker");
    let mut transcript = [0_u8; 32];
    transcript.copy_from_slice(&ready[4..]);
    ensure!(
        constant_time_eq(&transcript, &expected_transcript),
        "V2 session transcript mismatch"
    );
    Ok(())
}

fn endpoint_id(bytes: &[u8]) -> Result<EndpointId> {
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid V2 endpoint id length"))?;
    EndpointId::from_bytes(&raw).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use iroh::{
        Endpoint, EndpointAddr, RelayMode, SecretKey,
        endpoint::{ConnectOptions, TlsSessionPartition, presets},
    };

    use super::*;

    fn hello() -> SessionHelloV2 {
        SessionHelloV2 {
            role: ConnectionRole::Data,
            capabilities: capability::REQUIRED | capability::FEC_STRIPES | capability::LIVE_MEDIA,
            network_id: "production-v2".into(),
            local_id: SecretKey::from_bytes(&[1; 32]).public(),
            expected_remote_id: SecretKey::from_bytes(&[2; 32]).public(),
            limits: WireLimitsV2 {
                max_datagram_size: 1382,
                max_control_size: 64 * 1024,
                max_train_size: 32 * 1024,
                max_record_size: u16::MAX as u32,
                max_cells_per_train: 64,
                max_active_trains: 1024,
            },
            cover_profile_id: 7,
            nonce: [3; 32],
            exporter_binding: [4; 32],
            membership_proof: [5; 32],
        }
    }

    fn policy(local_id: EndpointId, remote_id: EndpointId, network_id: &str) -> SessionPolicyV2 {
        SessionPolicyV2 {
            network_id: network_id.into(),
            local_id,
            remote_id,
            role: ConnectionRole::Data,
            expected_remote_role: Some(ConnectionRole::Data),
            capabilities: capability::REQUIRED | capability::FEC_STRIPES | capability::LIVE_MEDIA,
            limits: hello().limits,
            cover_profile_id: 7,
        }
    }

    #[test]
    fn datagram_ceiling_negotiates_new_new_and_preserves_an_old_peer_floor() {
        let local = SecretKey::from_bytes(&[1; 32]).public();
        let remote = SecretKey::from_bytes(&[2; 32]).public();
        let mut local_policy = policy(local, remote, "production-v2");
        local_policy.limits.max_datagram_size = u16::MAX;
        local_policy.limits.max_train_size = 64 * 1024;

        let mut new_peer = hello();
        new_peer.limits.max_datagram_size = u16::MAX;
        new_peer.limits.max_train_size = 64 * 1024;
        let negotiated = negotiate(&local_policy, &new_peer, [7; 32]);
        assert_eq!(negotiated.limits.max_datagram_size, u16::MAX);

        let mut old_peer = new_peer;
        old_peer.limits.max_datagram_size = 1_382;
        let negotiated = negotiate(&local_policy, &old_peer, [8; 32]);
        assert_eq!(negotiated.limits.max_datagram_size, 1_382);
    }

    async fn connections() -> (Endpoint, Endpoint, Connection, Connection) {
        let alpn = b"h3".to_vec();
        let client = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::generate())
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let target =
            EndpointAddr::new(server.id()).with_ip_addr(*server.addr().ip_addrs().next().unwrap());
        let (client_connection, server_connection) = tokio::join!(
            async {
                client
                    .connect_with_opts(
                        target,
                        &alpn,
                        ConnectOptions::new()
                            .with_visible_server_name("live.example")
                            .with_tls_session_partition(TlsSessionPartition::new(
                                "production-v2",
                                7,
                                1,
                            )),
                    )
                    .await
                    .unwrap()
                    .await
            },
            async { server.accept().await.unwrap().accept().unwrap().await }
        );
        (
            client,
            server,
            client_connection.unwrap(),
            server_connection.unwrap(),
        )
    }

    #[test]
    fn session_hello_round_trips() {
        let hello = hello();
        assert_eq!(
            SessionHelloV2::decode(hello.encode().unwrap()).unwrap(),
            hello
        );
    }

    #[test]
    fn session_hello_rejects_unknown_capabilities() {
        let mut hello = hello();
        hello.capabilities |= 1 << 63;
        assert!(hello.encode().is_err());
    }

    #[test]
    fn session_hello_rejects_trailing_and_truncated_bytes() {
        let encoded = hello().encode().unwrap();
        assert!(SessionHelloV2::decode(encoded.slice(..encoded.len() - 1)).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(SessionHelloV2::decode(Bytes::from(trailing)).is_err());
    }

    #[test]
    fn session_hello_rejects_zero_bindings() {
        let mut hello = hello();
        hello.exporter_binding = [0; 32];
        assert!(hello.encode().is_err());
        hello = self::hello();
        hello.membership_proof = [0; 32];
        assert!(hello.encode().is_err());
    }

    #[tokio::test]
    async fn visible_sni_is_decoupled_from_authenticated_endpoint_id() {
        let alpn = b"h3".to_vec();
        let (client, server, _client_connection, server_connection) = connections().await;
        let address = *server.addr().ip_addrs().next().unwrap();
        let handshake = server_connection
            .handshake_data()
            .unwrap()
            .downcast::<noq_proto::crypto::rustls::HandshakeData>()
            .unwrap();
        assert_eq!(handshake.server_name.as_deref(), Some("live.example"));

        let wrong_target = EndpointAddr::new(SecretKey::generate().public()).with_ip_addr(address);
        let acceptor = server.clone();
        let wrong_server = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                acceptor.accept().await.unwrap().accept().unwrap().await
            })
            .await
        });
        let wrong_connecting = client
            .connect_with_opts(
                wrong_target,
                &alpn,
                ConnectOptions::new()
                    .with_visible_server_name("live.example")
                    .with_tls_session_partition(TlsSessionPartition::new("production-v2", 7, 1)),
            )
            .await
            .unwrap();
        let wrong_client =
            tokio::time::timeout(std::time::Duration::from_secs(2), wrong_connecting)
                .await
                .expect("wrong-peer handshake did not terminate");
        assert!(wrong_client.is_err());
        let _ = wrong_server.await;

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn v2_session_is_bound_to_tls_exporter_identity_and_network() {
        let (client, server, client_connection, server_connection) = connections().await;
        let client_policy = policy(client.id(), server.id(), "production-v2");
        let mut server_policy = policy(server.id(), client.id(), "production-v2");
        server_policy.limits.max_train_size = 16 * 1024;
        let (client_session, server_session) = tokio::join!(
            negotiate_connection_v2(&client_connection, &client_policy),
            negotiate_connection_v2(&server_connection, &server_policy)
        );
        let client_session = client_session.unwrap();
        let server_session = server_session.unwrap();
        assert_eq!(client_session, server_session);
        assert_eq!(client_session.limits.max_train_size, 16 * 1024);
        assert_ne!(client_session.session_epoch, 0);
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn v2_session_rejects_wrong_network_membership() {
        let (client, server, client_connection, server_connection) = connections().await;
        let client_policy = policy(client.id(), server.id(), "network-a");
        let server_policy = policy(server.id(), client.id(), "network-b");
        let (client_session, server_session) = tokio::join!(
            negotiate_connection_v2(&client_connection, &client_policy),
            negotiate_connection_v2(&server_connection, &server_policy)
        );
        assert!(client_session.is_err());
        assert!(server_session.is_err());
        client.close().await;
        server.close().await;
    }
}
