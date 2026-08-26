use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointId, SecretKey};
use tracing::info;

/// A side-effect-free decision to use the configured identity or provision a
/// new one as part of an explicit deployment transaction.
pub struct IdentityPlan {
    key: SecretKey,
    needs_creation: bool,
}

/// The result of committing an [`IdentityPlan`]. A caller that subsequently
/// fails its larger transaction can remove only the identity it created.
pub struct PersistedIdentity {
    key: SecretKey,
    created: bool,
    created_parents: Vec<std::path::PathBuf>,
}

impl IdentityPlan {
    /// Inspect a first-install path without mutating the filesystem. Missing
    /// identities are planned for creation, but only [`Self::persist`] writes.
    pub fn prepare_bootstrap(path: &Path) -> Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(Self {
                key: load(path)?,
                needs_creation: false,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                key: SecretKey::generate(),
                needs_creation: true,
            }),
            Err(error) => {
                Err(error).with_context(|| format!("failed to inspect {}", path.display()))
            }
        }
    }

    /// Bind an existing deployment to its already-provisioned identity.
    pub fn require(path: &Path) -> Result<Self> {
        Ok(Self {
            key: load(path)?,
            needs_creation: false,
        })
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.key.public()
    }

    /// Persist the plan. Creation uses `create_new`, so an existing identity
    /// is never replaced. A concurrent creator wins and is loaded instead.
    pub fn persist(&self, path: &Path) -> Result<PersistedIdentity> {
        if !self.needs_creation {
            return Ok(PersistedIdentity {
                key: self.key.clone(),
                created: false,
                created_parents: Vec::new(),
            });
        }

        let created_parents = create_private_parent(path)?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(mut file) => {
                if let Err(error) = write_key(&mut file, &self.key).and_then(|()| sync_parent(path))
                {
                    let _ = remove_created_identity(path, &self.key, &created_parents);
                    return Err(error);
                }
                info!(
                    identity_file = %path.display(),
                    endpoint_id = %self.key.public(),
                    "created persistent node identity"
                );
                Ok(PersistedIdentity {
                    key: self.key.clone(),
                    created: true,
                    created_parents,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Ok(PersistedIdentity {
                    key: load(path)?,
                    created: false,
                    created_parents,
                })
            }
            Err(error) => {
                remove_empty_directories(&created_parents);
                Err(error).with_context(|| format!("failed to create {}", path.display()))
            }
        }
    }
}

impl PersistedIdentity {
    pub fn key(&self) -> &SecretKey {
        &self.key
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.key.public()
    }

    /// Undo a newly created identity after its containing transaction fails.
    /// Existing identities are never removed.
    pub fn rollback_created(&self, path: &Path) -> Result<()> {
        if !self.created {
            return Ok(());
        }
        remove_created_identity(path, &self.key, &self.created_parents)
    }
}

/// Provision an identity for an explicit bootstrap operation. Runtime and
/// inspection paths must use [`load`] so a lost node key is surfaced instead
/// of silently changing the node's authenticated identity.
pub fn load_or_create(path: &Path) -> Result<SecretKey> {
    Ok(IdentityPlan::prepare_bootstrap(path)?
        .persist(path)?
        .key()
        .clone())
}

pub fn load(path: &Path) -> Result<SecretKey> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "identity {} must be a regular file and not a symlink",
        path.display()
    );
    let mode = metadata.permissions().mode() & 0o777;
    ensure!(
        mode & 0o077 == 0,
        "identity {} has insecure mode {mode:o}; expected 0600 or stricter",
        path.display()
    );
    let encoded = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    encoded
        .trim()
        .parse()
        .with_context(|| format!("invalid secret key in {}", path.display()))
}

pub fn backup(source: &Path, destination: &Path) -> Result<()> {
    let key = load(source)?;
    create_parent(destination)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .with_context(|| format!("failed to create backup {}", destination.display()))?;
    write_key(&mut file, &key)
}

pub fn restore(source: &Path, destination: &Path) -> Result<SecretKey> {
    if destination.exists() {
        bail!("identity already exists at {}", destination.display());
    }
    let key = load(source)?;
    create_private_parent(destination)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .with_context(|| format!("failed to restore {}", destination.display()))?;
    write_key(&mut file, &key)?;
    Ok(key)
}

fn create_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    Ok(())
}

fn create_private_parent(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let created_parents = missing_parent_directories(path)?;
    if let Some(parent) = path.parent() {
        // Apply the private mode only to directories created by this call.
        // Rechmodding an existing parent is unsafe: an identity placed below
        // /tmp, a state mount, or another shared directory must not change the
        // access mode of that directory for the entire host.
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(created_parents)
}

fn write_key(file: &mut std::fs::File, key: &SecretKey) -> Result<()> {
    writeln!(file, "{}", hex::encode(key.to_bytes()))?;
    file.sync_all()?;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)
        .with_context(|| format!("failed opening identity directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed persisting identity directory {}", parent.display()))
}

fn missing_parent_directories(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let Some(mut parent) = path.parent() else {
        return Ok(Vec::new());
    };
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(parent) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(parent.to_path_buf());
                let Some(next) = parent.parent() else {
                    break;
                };
                parent = next;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", parent.display()));
            }
        }
    }
    missing.reverse();
    Ok(missing)
}

fn remove_created_identity(
    path: &Path,
    key: &SecretKey,
    created_parents: &[std::path::PathBuf],
) -> Result<()> {
    let expected = format!("{}\n", hex::encode(key.to_bytes()));
    let actual = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading created identity {}", path.display()))?;
    ensure!(
        actual == expected,
        "refusing to remove identity {} because it changed after creation",
        path.display()
    );
    std::fs::remove_file(path)
        .with_context(|| format!("failed removing created identity {}", path.display()))?;
    sync_parent(path)?;
    remove_empty_directories(created_parents);
    Ok(())
}

fn remove_empty_directories(paths: &[std::path::PathBuf]) {
    for path in paths.iter().rev() {
        match std::fs::remove_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_persistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let first = load_or_create(&path).unwrap();
        let second = load_or_create(&path).unwrap();
        assert_eq!(first.public(), second.public());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn identity_plan_is_side_effect_free_until_committed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/identity.key");

        let plan = IdentityPlan::prepare_bootstrap(&path).unwrap();
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());

        let identity = plan.persist(&path).unwrap();
        assert_eq!(identity.endpoint_id(), load(&path).unwrap().public());
    }

    #[test]
    fn rolled_back_plan_removes_only_its_new_identity_and_empty_parent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/identity.key");
        let parent = path.parent().unwrap().to_path_buf();

        let identity = IdentityPlan::prepare_bootstrap(&path)
            .unwrap()
            .persist(&path)
            .unwrap();
        identity.rollback_created(&path).unwrap();

        assert!(!path.exists());
        assert!(!parent.exists());
    }

    #[test]
    fn rejects_group_readable_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        std::fs::write(&path, hex::encode(SecretKey::generate().to_bytes())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            load(&path)
                .unwrap_err()
                .to_string()
                .contains("insecure mode")
        );
    }

    #[test]
    fn backup_and_restore_preserve_identity_securely() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("identity.key");
        let backup_path = dir.path().join("backup.key");
        let restored_path = dir.path().join("restored/identity.key");
        let original = load_or_create(&source).unwrap();
        backup(&source, &backup_path).unwrap();
        let restored = restore(&backup_path, &restored_path).unwrap();
        assert_eq!(original.public(), restored.public());
        assert_eq!(
            std::fs::metadata(restored_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn identity_creation_preserves_existing_parent_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("identity.key");

        load_or_create(&path).unwrap();

        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
