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
    let key = identity::load(&config.identity_file)?;
    let endpoint_id = key.public();
    config.validate_local_id(endpoint_id)?;
    Ok((config, endpoint_id))
}

pub async fn install(source: &Path, destination: &Path) -> Result<()> {
    if source == destination {
        bail!("source and destination configuration paths must differ");
    }
    let config = Config::load_unsealed(source).await?;
    let candidate = read_file(source)?;
    let previous = previous_path(destination);
    let destination_digest = config_digest_path(destination);
    let previous_digest = config_digest_path(&previous);
    let destination_snapshot = FileSnapshot::capture(destination)?;
    let destination_digest_snapshot = FileSnapshot::capture(&destination_digest)?;
    let previous_snapshot = FileSnapshot::capture(&previous)?;
    let previous_digest_snapshot = FileSnapshot::capture(&previous_digest)?;
    let identity_plan = if destination_snapshot.contents().is_some() {
        identity::IdentityPlan::require(&config.identity_file)?
    } else {
        identity::IdentityPlan::prepare_bootstrap(&config.identity_file)?
    };
    config.validate_local_id(identity_plan.endpoint_id())?;

    let persisted_identity = identity_plan.persist(&config.identity_file)?;
    if let Err(error) = config.validate_local_id(persisted_identity.endpoint_id()) {
        return rollback_identity_after_failure(error, &persisted_identity, &config.identity_file);
    }

    let result = (|| -> Result<()> {
        if let Some(current) = destination_snapshot.contents() {
            atomic_write(&previous, current, 0o600)?;
            write_digest(&previous, current)?;
        }
        atomic_write(destination, &candidate, 0o600)?;
        write_digest(destination, &candidate)
    })();
    if let Err(error) = result {
        return rollback_install_after_failure(
            error,
            [
                &destination_snapshot,
                &destination_digest_snapshot,
                &previous_snapshot,
                &previous_digest_snapshot,
            ],
            &persisted_identity,
            &config.identity_file,
        );
    }

    info!(
        source = %source.display(),
        destination = %destination.display(),
        endpoint_id = %persisted_identity.endpoint_id(),
        network_id = %config.network_id,
        "configuration installed atomically"
    );
    Ok(())
}

pub async fn seal(path: &Path) -> Result<()> {
    let config = Config::load_unsealed(path).await?;
    let identity_plan = if config_digest_exists(path)? {
        identity::IdentityPlan::require(&config.identity_file)?
    } else {
        identity::IdentityPlan::prepare_bootstrap(&config.identity_file)?
    };
    config.validate_local_id(identity_plan.endpoint_id())?;
    let contents = read_file(path)?;
    let persisted_identity = identity_plan.persist(&config.identity_file)?;
    if let Err(error) = config.validate_local_id(persisted_identity.endpoint_id()) {
        return rollback_identity_after_failure(error, &persisted_identity, &config.identity_file);
    }
    if let Err(error) = write_digest(path, &contents) {
        return rollback_identity_after_failure(error, &persisted_identity, &config.identity_file);
    }
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

fn config_digest_exists(config_path: &Path) -> Result<bool> {
    let digest_path = config_digest_path(config_path);
    match std::fs::symlink_metadata(&digest_path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed inspecting {}", digest_path.display()))
        }
    }
}

fn write_digest(config_path: &Path, contents: &[u8]) -> Result<()> {
    let digest = format!("{}\n", blake3::hash(contents).to_hex());
    atomic_write(&config_digest_path(config_path), digest.as_bytes(), 0o600)
}

struct FileSnapshot {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

impl FileSnapshot {
    fn capture(path: &Path) -> Result<Self> {
        let contents = match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    bail!("refusing to replace non-regular file {}", path.display());
                }
                Some(read_file(path)?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| format!("failed inspecting {}", path.display()));
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            contents,
        })
    }

    fn contents(&self) -> Option<&[u8]> {
        self.contents.as_deref()
    }

    fn restore(&self) -> Result<()> {
        match &self.contents {
            Some(contents) => atomic_write(&self.path, contents, 0o600),
            None => remove_file_if_exists(&self.path),
        }
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            File::open(parent)
                .with_context(|| format!("failed opening {}", parent.display()))?
                .sync_all()
                .with_context(|| format!("failed persisting {}", parent.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed removing {}", path.display())),
    }
}

fn rollback_identity_after_failure<T>(
    error: anyhow::Error,
    identity: &identity::PersistedIdentity,
    identity_path: &Path,
) -> Result<T> {
    match identity.rollback_created(identity_path) {
        Ok(()) => Err(error),
        Err(rollback) => Err(error.context(format!(
            "identity provisioning rollback also failed: {rollback:#}"
        ))),
    }
}

fn rollback_install_after_failure<T>(
    error: anyhow::Error,
    snapshots: [&FileSnapshot; 4],
    identity: &identity::PersistedIdentity,
    identity_path: &Path,
) -> Result<T> {
    let restore_errors = snapshots
        .into_iter()
        .rev()
        .filter_map(|snapshot| snapshot.restore().err().map(|error| format!("{error:#}")))
        .collect::<Vec<_>>();
    let identity_error = identity.rollback_created(identity_path).err();
    match (restore_errors.is_empty(), identity_error) {
        (true, None) => Err(error),
        (false, None) => Err(error.context(format!(
            "configuration install rollback also failed: {}",
            restore_errors.join("; ")
        ))),
        (true, Some(identity)) => Err(error.context(format!(
            "identity provisioning rollback also failed: {identity:#}"
        ))),
        (false, Some(identity)) => Err(error.context(format!(
            "configuration rollback failed: {}; identity rollback failed: {identity:#}",
            restore_errors.join("; ")
        ))),
    }
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
    async fn sealing_an_existing_configuration_requires_its_identity() {
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
        std::fs::remove_file(&identity_path).unwrap();

        let error = seal(&config_path).await.unwrap_err();

        assert!(error.to_string().contains("failed to inspect"));
        assert!(!identity_path.exists());
    }

    #[tokio::test]
    async fn validation_does_not_create_a_missing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let identity_path = dir.path().join("state/identity.key");
        let contents = format!(
            "network_id = \"bootstrap\"\nidentity_file = \"{}\"\n",
            identity_path.display()
        );
        atomic_write(&config_path, contents.as_bytes(), 0o600).unwrap();
        write_digest(&config_path, contents.as_bytes()).unwrap();

        let error = validate(&config_path).await.unwrap_err();

        assert!(error.to_string().contains("failed to inspect"));
        assert!(!identity_path.exists());
        assert!(!identity_path.parent().unwrap().exists());
    }

    #[tokio::test]
    async fn failed_install_removes_a_newly_provisioned_identity() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("candidate.toml");
        let identity_path = dir.path().join("state/identity.key");
        atomic_write(
            &source,
            format!(
                "network_id = \"bootstrap\"\nidentity_file = \"{}\"\n",
                identity_path.display()
            )
            .as_bytes(),
            0o600,
        )
        .unwrap();
        let destination = Path::new("/proc/ironet-install-identity-rollback/config.toml");

        let error = install(&source, destination).await.unwrap_err();

        assert!(error.to_string().contains("failed creating"));
        assert!(!identity_path.exists());
        assert!(!identity_path.parent().unwrap().exists());
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
