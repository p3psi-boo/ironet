use std::{net::SocketAddr, num::NonZeroU32, time::Duration};

use anyhow::{Context, Result};
use iroh::EndpointId;
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    hmac, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::json_line;

pub(crate) const PROTOCOL_VERSION: u8 = 1;
pub(crate) const PASSWORD_KEY_BYTES: usize = 32;
pub(crate) const PASSWORD_SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 32;
const AEAD_NONCE_BYTES: usize = 12;
pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024;
pub(crate) const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(15);
const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(600_000).expect("non-zero PBKDF2 count");
const PROOF_DOMAIN: &[u8] = b"ironet-password-enrollment/v1/proof\0";
const INVITE_AAD: &[u8] = b"ironet-password-enrollment/v1/invite";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EnrollmentRequest {
    Join {
        version: u8,
        bootstrap: SocketAddr,
        member_endpoint_id: EndpointId,
    },
    Confirm {
        version: u8,
        invite_id: String,
        member_endpoint_id: EndpointId,
    },
}

impl EnrollmentRequest {
    pub(crate) fn version(&self) -> u8 {
        match self {
            Self::Join { version, .. } | Self::Confirm { version, .. } => *version,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentChallenge {
    pub(crate) version: u8,
    pub(crate) salt: String,
    pub(crate) nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentProof {
    pub(crate) proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentResult {
    pub(crate) version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) invite_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) invite_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) encrypted_invite: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

pub(crate) fn derive_password_key(password: &[u8], salt: &[u8]) -> [u8; PASSWORD_KEY_BYTES] {
    let mut key = [0_u8; PASSWORD_KEY_BYTES];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PBKDF2_ITERATIONS,
        salt,
        password,
        &mut key,
    );
    key
}

pub(crate) fn make_proof(
    key: &[u8; PASSWORD_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    request: &EnrollmentRequest,
) -> [u8; PASSWORD_KEY_BYTES] {
    let proof = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &proof_message(nonce, request),
    );
    proof.as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
}

pub(crate) fn proof_is_valid(
    key: &[u8; PASSWORD_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    request: &EnrollmentRequest,
    proof: &[u8; PASSWORD_KEY_BYTES],
) -> bool {
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &proof_message(nonce, request),
        proof,
    )
    .is_ok()
}

fn proof_message(nonce: &[u8; NONCE_BYTES], request: &EnrollmentRequest) -> Vec<u8> {
    let mut message = Vec::with_capacity(PROOF_DOMAIN.len() + nonce.len() + 128);
    message.extend_from_slice(PROOF_DOMAIN);
    message.extend_from_slice(nonce);
    match request {
        EnrollmentRequest::Join {
            bootstrap,
            member_endpoint_id,
            ..
        } => {
            append_field(&mut message, b"join");
            append_field(&mut message, bootstrap.to_string().as_bytes());
            append_field(&mut message, member_endpoint_id.to_string().as_bytes());
        }
        EnrollmentRequest::Confirm {
            invite_id,
            member_endpoint_id,
            ..
        } => {
            append_field(&mut message, b"confirm");
            append_field(&mut message, invite_id.as_bytes());
            append_field(&mut message, member_endpoint_id.to_string().as_bytes());
        }
    }
    message
}

fn append_field(message: &mut Vec<u8>, field: &[u8]) {
    message.extend_from_slice(&(field.len() as u64).to_be_bytes());
    message.extend_from_slice(field);
}

pub(crate) fn encrypt_invite(
    key: &[u8; PASSWORD_KEY_BYTES],
    invite: &str,
) -> Result<(String, String)> {
    let nonce = random_bytes::<AEAD_NONCE_BYTES>()?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow::anyhow!("invalid password key"))?,
    );
    let mut encrypted = invite.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(INVITE_AAD),
        &mut encrypted,
    )
    .map_err(|_| anyhow::anyhow!("encrypting password enrollment invite failed"))?;
    Ok((hex::encode(nonce), hex::encode(encrypted)))
}

pub(crate) fn decrypt_invite(
    key: &[u8; PASSWORD_KEY_BYTES],
    encoded_nonce: &str,
    encoded_invite: &str,
) -> Result<String> {
    let nonce = decode_fixed::<AEAD_NONCE_BYTES>(encoded_nonce, "encrypted invite nonce")?;
    let mut encrypted = hex::decode(encoded_invite).context("encrypted invite is not valid hex")?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow::anyhow!("invalid password key"))?,
    );
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(INVITE_AAD),
            &mut encrypted,
        )
        .map_err(|_| anyhow::anyhow!("password enrollment response could not be decrypted"))?;
    String::from_utf8(plaintext.to_vec()).context("password enrollment invite is not UTF-8")
}

pub(crate) fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let value = hex::decode(value).with_context(|| format!("{field} is not valid hex"))?;
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must contain exactly {N} bytes"))
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("reading system randomness failed"))?;
    Ok(bytes)
}

pub(crate) async fn read_json<T, R>(reader: &mut R) -> Result<T>
where
    T: DeserializeOwned,
    R: AsyncBufRead + Unpin,
{
    tokio::time::timeout(PROTOCOL_TIMEOUT, json_line::read(reader, MAX_FRAME_BYTES))
        .await
        .context("timed out reading password enrollment frame")?
        .context("invalid password enrollment frame")
}

pub(crate) async fn write_json<T, W>(writer: &mut W, value: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(
        PROTOCOL_TIMEOUT,
        json_line::write(writer, value, MAX_FRAME_BYTES),
    )
    .await
    .context("timed out writing password enrollment frame")?
    .context("writing password enrollment frame")
}

pub(crate) fn successful_result() -> EnrollmentResult {
    EnrollmentResult {
        version: PROTOCOL_VERSION,
        invite_id: None,
        invite_nonce: None,
        encrypted_invite: None,
        error: None,
    }
}

pub(crate) fn rejection_result() -> EnrollmentResult {
    EnrollmentResult {
        version: PROTOCOL_VERSION,
        invite_id: None,
        invite_nonce: None,
        encrypted_invite: None,
        error: Some("access_denied".into()),
    }
}
