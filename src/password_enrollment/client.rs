use std::net::SocketAddr;

use anyhow::{Context, Result, bail, ensure};
use iroh::EndpointId;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

use super::protocol::{
    EnrollmentChallenge, EnrollmentProof, EnrollmentRequest, EnrollmentResult, PASSWORD_KEY_BYTES,
    PASSWORD_SALT_BYTES, PROTOCOL_TIMEOUT, PROTOCOL_VERSION, decode_fixed, decrypt_invite,
    derive_password_key, make_proof, read_json, write_json,
};

#[derive(Debug)]
pub struct EnrollmentTicket {
    pub invite: String,
    pub invite_id: String,
}

pub async fn enroll(
    peer: SocketAddr,
    password: &[u8],
    member_endpoint_id: EndpointId,
) -> Result<EnrollmentTicket> {
    let request = EnrollmentRequest::Join {
        version: PROTOCOL_VERSION,
        bootstrap: peer,
        member_endpoint_id,
    };
    let (mut read, mut write, key) = authenticate(peer, password, &request).await?;
    let result = read_result(&mut read).await?;
    let invite_id = result
        .invite_id
        .context("password enrollment response omitted invite id")?;
    let invite_nonce = result
        .invite_nonce
        .context("password enrollment response omitted invite nonce")?;
    let encrypted_invite = result
        .encrypted_invite
        .context("password enrollment response omitted encrypted invite")?;
    let invite = decrypt_invite(&key, &invite_nonce, &encrypted_invite)?;
    write.shutdown().await?;
    Ok(EnrollmentTicket { invite, invite_id })
}

pub async fn confirm(
    peer: SocketAddr,
    password: &[u8],
    member_endpoint_id: EndpointId,
    invite_id: &str,
) -> Result<()> {
    let request = EnrollmentRequest::Confirm {
        version: PROTOCOL_VERSION,
        invite_id: invite_id.into(),
        member_endpoint_id,
    };
    let (mut read, mut write, _) = authenticate(peer, password, &request).await?;
    read_result(&mut read).await?;
    write.shutdown().await?;
    Ok(())
}

async fn authenticate(
    peer: SocketAddr,
    password: &[u8],
    request: &EnrollmentRequest,
) -> Result<(
    BufReader<OwnedReadHalf>,
    OwnedWriteHalf,
    [u8; PASSWORD_KEY_BYTES],
)> {
    ensure!(!password.is_empty(), "password file cannot be empty");
    let stream = tokio::time::timeout(PROTOCOL_TIMEOUT, TcpStream::connect(peer))
        .await
        .context("timed out connecting to password enrollment listener")?
        .with_context(|| format!("connecting to password enrollment listener at {peer}"))?;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write_json(&mut write, request).await?;
    let challenge: EnrollmentChallenge = read_json(&mut read).await?;
    ensure!(
        challenge.version == PROTOCOL_VERSION,
        "unsupported password enrollment protocol version {}",
        challenge.version
    );
    let salt = decode_fixed::<PASSWORD_SALT_BYTES>(&challenge.salt, "enrollment salt")?;
    let nonce = decode_fixed::<32>(&challenge.nonce, "enrollment nonce")?;
    let key = derive_password_key(password, &salt);
    write_json(
        &mut write,
        &EnrollmentProof {
            proof: hex::encode(make_proof(&key, &nonce, request)),
        },
    )
    .await?;
    Ok((read, write, key))
}

async fn read_result(read: &mut BufReader<OwnedReadHalf>) -> Result<EnrollmentResult> {
    let result: EnrollmentResult = read_json(read).await?;
    ensure!(
        result.version == PROTOCOL_VERSION,
        "unsupported password enrollment result version {}",
        result.version
    );
    if let Some(error) = result.error.as_deref() {
        bail!("password enrollment rejected: {error}");
    }
    Ok(result)
}
