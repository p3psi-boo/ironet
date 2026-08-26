//! Product-state persistence and recoverable multi-file updates.

use super::*;

pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PRODUCT_STATE_FILE)
}

pub fn authority_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join(AUTHORITY_KEY_FILE)
}

pub fn default_node_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "ironet-node".into())
}

pub fn load_state(state_dir: &Path) -> Result<ProductState> {
    let path = state_path(state_dir);
    let raw = fs::read_to_string(&path).with_context(|| {
        format!(
            "this machine has not joined an ironet network ({})",
            path.display()
        )
    })?;
    let mut state: ProductState = toml::from_str(&raw)
        .with_context(|| format!("failed to parse product state {}", path.display()))?;
    ensure!(
        (1..=PRODUCT_STATE_VERSION).contains(&state.version),
        "unsupported product state version {}",
        state.version
    );
    // Product state is local deployment metadata, not a wire-protocol
    // compatibility surface.  Version 1 already carries the V2 identity,
    // authority and address-plan data needed here; normalize it in memory so
    // the next transactional write upgrades it atomically to the current
    // schema.  This keeps an in-place binary upgrade from stranding an
    // otherwise valid V2 deployment.
    state.version = PRODUCT_STATE_VERSION;
    Ok(state)
}

pub fn save_state(state_dir: &Path, state: &ProductState) -> Result<()> {
    ensure_private_dir(state_dir)?;
    let encoded = toml::to_string_pretty(state)?;
    deployment::atomic_write(&state_path(state_dir), encoded.as_bytes(), 0o600)
}

pub(super) fn save_invite_transaction(
    config_path: &Path,
    state_dir: &Path,
    config: &Config,
    state: &ProductState,
) -> Result<()> {
    let digest_path = config_digest_path(config_path);
    let product_path = state_path(state_dir);
    let encoded_config = toml::to_string_pretty(config)?;
    let encoded_state = toml::to_string_pretty(state)?;
    let transaction = deployment::FileTransaction::capture([
        config_path,
        digest_path.as_path(),
        product_path.as_path(),
    ])?;

    let result = (|| -> Result<()> {
        deployment::write_sealed_config(config_path, encoded_config.as_bytes())?;
        deployment::atomic_write(&product_path, encoded_state.as_bytes(), 0o600)?;
        Ok(())
    })();
    if let Err(error) = result {
        return transaction.rollback(error, "invite creation");
    }
    Ok(())
}

pub(super) fn write_bundle(
    config_path: &Path,
    state_dir: &Path,
    config: &Config,
    state: &ProductState,
    node_key: &SecretKey,
    write_node_key: bool,
    authority: Option<(&Path, &SecretKey)>,
) -> Result<()> {
    ensure_private_dir(state_dir)?;
    let identity_file = config.identity_file.clone();
    let route_file = config.route_registry_path();
    let product_file = state_path(state_dir);
    let digest_file = config_digest_path(config_path);
    let mut paths = vec![
        identity_file.as_path(),
        config_path,
        digest_file.as_path(),
        route_file.as_path(),
        product_file.as_path(),
    ];
    if let Some((path, _)) = authority {
        paths.push(path);
    }
    let transaction = deployment::FileTransaction::capture(paths)?;
    let result = (|| -> Result<()> {
        if write_node_key {
            write_secret(&identity_file, node_key)?;
        }
        if let Some((path, key)) = authority {
            write_secret(path, key)?;
        }
        let encoded = toml::to_string_pretty(config)?;
        deployment::write_sealed_config(config_path, encoded.as_bytes())?;
        RouteRegistry::default().write(&route_file)?;
        save_state(state_dir, state)?;
        Ok(())
    })();
    if let Err(error) = result {
        return transaction.rollback(error, "network setup");
    }
    Ok(())
}

pub(super) async fn update_config(
    config_path: &Path,
    mutate: impl FnOnce(&mut Config) -> Result<()>,
) -> Result<()> {
    update_config_transaction(config_path, None, mutate).await
}

pub(super) async fn update_config_and_state(
    config_path: &Path,
    state_dir: &Path,
    state: &ProductState,
    mutate: impl FnOnce(&mut Config) -> Result<()>,
) -> Result<()> {
    update_config_transaction(config_path, Some((state_dir, state)), mutate).await
}

async fn update_config_transaction(
    config_path: &Path,
    state: Option<(&Path, &ProductState)>,
    mutate: impl FnOnce(&mut Config) -> Result<()>,
) -> Result<()> {
    let mut config = Config::load(config_path).await?;
    mutate(&mut config)?;
    config.validate()?;
    let key = identity::load(&config.identity_file)?;
    config.validate_local_id(key.public())?;
    let encoded = toml::to_string_pretty(&config)?;
    let digest_path = config_digest_path(config_path);
    let state_path = state.map(|(state_dir, _)| state_path(state_dir));
    let mut paths = vec![config_path, digest_path.as_path()];
    if let Some(path) = state_path.as_deref() {
        paths.push(path);
    }
    let transaction = deployment::FileTransaction::capture(paths)?;
    let result = (|| -> Result<()> {
        deployment::write_sealed_config(config_path, encoded.as_bytes())?;
        if let Some((state_dir, state)) = state {
            save_state(state_dir, state)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        return transaction.rollback(error, "configuration update");
    }
    Ok(())
}

pub(super) fn load_sealed_sync(path: &Path) -> Result<Config> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    let expected = fs::read_to_string(config_digest_path(path)).with_context(|| {
        format!(
            "missing configuration integrity file for {}",
            path.display()
        )
    })?;
    ensure!(
        expected.trim() == blake3::hash(raw.as_bytes()).to_hex().as_str(),
        "configuration integrity check failed for {}",
        path.display()
    );
    toml::from_str(&raw).with_context(|| format!("failed parsing {}", path.display()))
}

fn write_secret(path: &Path, key: &SecretKey) -> Result<()> {
    deployment::atomic_write(
        path,
        format!("{}\n", hex::encode(key.to_bytes())).as_bytes(),
        0o600,
    )
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed creating {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed securing {}", path.display()))
}
