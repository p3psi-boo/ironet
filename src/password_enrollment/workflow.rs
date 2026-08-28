//! Crash-safe member-side password enrollment orchestration.

use std::{net::SocketAddr, path::Path};

use anyhow::{Context, Result, ensure};

use crate::{config::Config, identity, product};

/// Join through password enrollment, or finish the one pending confirmation
/// left by an earlier locally committed join. Once confirmation is complete,
/// subsequent calls are entirely local and do not depend on the authority.
pub async fn join_network(
    config_path: &Path,
    state_dir: &Path,
    peer: SocketAddr,
    password: &[u8],
    node_name: Option<String>,
) -> Result<product::NetworkSummary> {
    ensure!(!password.is_empty(), "password file cannot be empty");
    let product_state_path = product::state_path(state_dir);
    match (config_path.exists(), product_state_path.exists()) {
        (true, true) => {
            let state = product::load_state(state_dir)?;
            let summary = product::show_network(config_path, state_dir).await?;
            if let Some(confirmation) = state.pending_password_confirmation {
                let config = Config::load(config_path).await?;
                let member_endpoint_id = identity::load(&config.identity_file)?.public();
                ensure!(
                    member_endpoint_id == confirmation.member_endpoint_id,
                    "pending password enrollment belongs to a different local identity"
                );
                super::confirm(peer, password, member_endpoint_id, &confirmation.invite_id).await?;
                product::complete_password_enrollment_confirmation(
                    state_dir,
                    &confirmation.invite_id,
                    member_endpoint_id,
                )?;
            }
            Ok(summary)
        }
        (false, false) => {
            let identity_path = state_dir.join("identity.key");
            // Persist first and use the committed winner. IdentityPlan permits a
            // concurrent creator to win, so deriving the enrollment identity
            // from the plan before this point would bind the invite to a key
            // which may never reach disk.
            let persisted = identity::IdentityPlan::prepare_bootstrap(&identity_path)?
                .persist(&identity_path)?;
            let member_endpoint_id = persisted.endpoint_id();
            let ticket = super::enroll(peer, password, member_endpoint_id).await?;
            let confirmation = product::PasswordEnrollmentConfirmation {
                invite_id: ticket.invite_id,
                member_endpoint_id,
            };
            let summary = product::join_network_with_confirmation(
                config_path,
                state_dir,
                &ticket.invite,
                node_name,
                true,
                Some(confirmation.clone()),
            )
            .await?;
            super::confirm(peer, password, member_endpoint_id, &confirmation.invite_id)
                .await
                .context("confirming locally committed password enrollment")?;
            product::complete_password_enrollment_confirmation(
                state_dir,
                &confirmation.invite_id,
                member_endpoint_id,
            )?;
            Ok(summary)
        }
        _ => anyhow::bail!(
            "local network setup is incomplete: {} and {} must either both exist or both be absent",
            config_path.display(),
            product_state_path.display()
        ),
    }
}
