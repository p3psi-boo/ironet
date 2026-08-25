use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, chown},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use tracing::info;

use crate::{
    config::{Config, config_digest_path},
    identity,
};

pub async fn validate(path: &Path) -> Result<(Config, iroh::EndpointId)> {
    let config = Config::load(path).await?;
    let key = identity::load_or_create(&config.identity_file)?;
    let endpoint_id = key.public();
    config.validate_local_id(endpoint_id)?;
    Ok((config, endpoint_id))
}

pub async fn install(source: &Path, destination: &Path) -> Result<()> {
    if source == destination {
        bail!("source and destination configuration paths must differ");
    }
    let config = Config::load_unsealed(source).await?;
    let key = identity::load_or_create(&config.identity_file)?;
    let endpoint_id = key.public();
    config.validate_local_id(endpoint_id)?;
    let candidate = read_file(source)?;
    let previous = previous_path(destination);
    if destination.exists() {
        let current = read_file(destination)?;
        atomic_write(&previous, &current, 0o600)?;
        seal(&previous).await?;
    }
    atomic_write(destination, &candidate, 0o600)?;
    seal(destination).await?;
    info!(
        source = %source.display(),
        destination = %destination.display(),
        endpoint_id = %endpoint_id,
        network_id = %config.network_id,
        "configuration installed atomically"
    );
    Ok(())
}

pub async fn seal(path: &Path) -> Result<()> {
    let config = Config::load_unsealed(path).await?;
    let key = identity::load_or_create(&config.identity_file)?;
    config.validate_local_id(key.public())?;
    let contents = read_file(path)?;
    let digest = format!("{}\n", blake3::hash(&contents).to_hex());
    atomic_write(&config_digest_path(path), digest.as_bytes(), 0o600)?;
    info!(config = %path.display(), "configuration integrity digest written");
    Ok(())
}

pub async fn rollback(destination: &Path) -> Result<()> {
    let previous = previous_path(destination);
    let (config, endpoint_id) = validate(&previous).await?;
    let previous_data = read_file(&previous)?;
    let current_data = read_file(destination)?;
    atomic_write(destination, &previous_data, 0o600)?;
    seal(destination).await?;
    atomic_write(&previous, &current_data, 0o600)?;
    seal(&previous).await?;
    info!(
        destination = %destination.display(),
        endpoint_id = %endpoint_id,
        network_id = %config.network_id,
        "configuration rolled back atomically"
    );
    Ok(())
}

pub fn previous_path(path: &Path) -> PathBuf {
    path_with_suffix(path, ".previous")
}

pub fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed creating {}", parent.display()))?;
    let existing = match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                bail!("refusing to replace non-regular file {}", path.display());
            }
            Some((
                metadata.uid(),
                metadata.gid(),
                metadata.permissions().mode() & 0o777,
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("failed inspecting {}", path.display()));
        }
    };
    let temporary = temporary_path(path);
    let _ = std::fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(existing.map_or(mode, |(_, _, mode)| mode))
        .open(&temporary)
        .with_context(|| format!("failed creating {}", temporary.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    if let Some((uid, gid, mode)) = existing {
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(mode))?;
        chown(&temporary, Some(uid), Some(gid))
            .with_context(|| format!("failed preserving ownership for {}", path.display()))?;
    }
    std::fs::rename(&temporary, path)
        .with_context(|| format!("failed replacing {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    path_with_suffix(path, &format!(".new-{}", std::process::id()))
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("failed reading {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_complete_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        atomic_write(&path, b"first", 0o600).unwrap();
        atomic_write(&path, b"second", 0o600).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_preserves_existing_access_contract() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        atomic_write(&path, b"first", 0o640).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        atomic_write(&path, b"second", 0o600).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.permissions().mode() & 0o777, 0o640);
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
    }

    #[tokio::test]
    async fn sealing_a_new_configuration_creates_and_persists_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let identity_path = dir.path().join("state/identity.key");
        atomic_write(
            &config_path,
            format!(
                "network_id = \"bootstrap\"\nidentity_file = \"{}\"\n",
                identity_path.display()
            )
            .as_bytes(),
            0o600,
        )
        .unwrap();

        seal(&config_path).await.unwrap();
        let created = identity::load(&identity_path).unwrap();
        let (_, endpoint_id) = validate(&config_path).await.unwrap();

        assert_eq!(endpoint_id, created.public());
        assert_eq!(
            identity::load(&identity_path).unwrap().public(),
            created.public()
        );
        assert!(config_digest_path(&config_path).exists());
    }

    #[tokio::test]
    async fn install_and_rollback_preserve_valid_generations() {
        let dir = tempfile::tempdir().unwrap();
        let identity_path = dir.path().join("identity.key");
        identity::load_or_create(&identity_path).unwrap();
        let active = dir.path().join("config.toml");
        let candidate = dir.path().join("candidate.toml");

        let mut current: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        current.network_id = "current".into();
        current.identity_file = identity_path.clone();
        current.peers.clear();
        current.route_origins.clear();
        atomic_write(
            &active,
            toml::to_string_pretty(&current).unwrap().as_bytes(),
            0o600,
        )
        .unwrap();
        seal(&active).await.unwrap();

        let mut next = current.clone();
        next.network_id = "candidate".into();
        atomic_write(
            &candidate,
            toml::to_string_pretty(&next).unwrap().as_bytes(),
            0o600,
        )
        .unwrap();

        install(&candidate, &active).await.unwrap();
        assert_eq!(Config::load(&active).await.unwrap().network_id, "candidate");
        assert_eq!(
            Config::load(&previous_path(&active))
                .await
                .unwrap()
                .network_id,
            "current"
        );

        rollback(&active).await.unwrap();
        assert_eq!(Config::load(&active).await.unwrap().network_id, "current");
        assert_eq!(
            Config::load(&previous_path(&active))
                .await
                .unwrap()
                .network_id,
            "candidate"
        );
    }
}
