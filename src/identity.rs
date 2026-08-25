use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use iroh::SecretKey;
use tracing::info;

/// Load a durable node identity, creating and persisting one on first use.
///
/// Creation uses `create_new`, so an existing identity is never replaced.
pub fn load_or_create(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        return load(path);
    }

    create_private_parent(path)?;

    let key = SecretKey::generate();
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            write_key(&mut file, &key)?;
            sync_parent(path)?;
            info!(
                identity_file = %path.display(),
                endpoint_id = %key.public(),
                "created persistent node identity"
            );
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => load(path),
        Err(error) => Err(error).with_context(|| format!("failed to create {}", path.display())),
    }
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

fn create_private_parent(path: &Path) -> Result<()> {
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
    Ok(())
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
