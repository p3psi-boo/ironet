//! Password-gated enrollment for declarative clients.
//!
//! The public UX is intentionally small: an authority enables password
//! enrollment when creating a network, then a client supplies only the
//! authority's `IP:PORT` and a password file. Membership itself remains the
//! existing signed-invite model; this module only provides a password-gated,
//! recoverable way to issue that invite.

mod client;
mod protocol;
mod server;
mod workflow;

use std::path::Path;

use anyhow::{Context, Result, ensure};
use ring::hmac;

use crate::config::{DEFAULT_PASSWORD_ENROLLMENT_INVITE_TTL_SECS, PasswordEnrollmentConfig};

pub use client::{EnrollmentTicket, confirm, enroll};
pub(crate) use server::{ListenerControl, ListenerServer};
pub use workflow::join_network;

pub fn read_password_file(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path != Path::new("-"),
        "password input must be a regular secret file"
    );
    let mut password = std::fs::read(path)
        .with_context(|| format!("failed reading password file {}", path.display()))?;
    while matches!(password.last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    ensure!(
        !password.is_empty(),
        "password file {} is empty",
        path.display()
    );
    Ok(password)
}

/// Build the sealed configuration fragment stored by an authority. The
/// clear-text password stays in the caller's secret file; the sealed config
/// contains only PBKDF2 output and its random salt.
pub fn create_config(password: &[u8]) -> Result<PasswordEnrollmentConfig> {
    ensure!(!password.is_empty(), "password file cannot be empty");
    let salt = protocol::random_bytes::<{ protocol::PASSWORD_SALT_BYTES }>()?;
    let key = protocol::derive_password_key(password, &salt);
    Ok(PasswordEnrollmentConfig {
        salt: hex::encode(salt),
        password_key: hex::encode(key),
        invite_ttl_secs: DEFAULT_PASSWORD_ENROLLMENT_INVITE_TTL_SECS,
    })
}

pub fn password_matches(password: &[u8], config: &PasswordEnrollmentConfig) -> Result<bool> {
    config.validate()?;
    ensure!(!password.is_empty(), "password file cannot be empty");
    let salt = protocol::decode_fixed::<{ protocol::PASSWORD_SALT_BYTES }>(
        &config.salt,
        "configured password salt",
    )?;
    let expected = protocol::decode_fixed::<{ protocol::PASSWORD_KEY_BYTES }>(
        &config.password_key,
        "configured password key",
    )?;
    let actual = protocol::derive_password_key(password, &salt);
    Ok(hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, &expected),
        b"ironet-password-enrollment/password-match",
        hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &actual),
            b"ironet-password-enrollment/password-match",
        )
        .as_ref(),
    )
    .is_ok())
}

#[cfg(test)]
mod tests;
