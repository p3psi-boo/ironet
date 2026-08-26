//! Verified policy-package loading and startup self-checks.

use super::*;

/// A package loader which verifies, compiles and self-checks policy components.
#[derive(Clone)]
pub struct PolicyLoader {
    engine: PolicyEngine,
    store_pool_capacity: usize,
}

impl fmt::Debug for PolicyLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyLoader")
            .field("store_pool_capacity", &self.store_pool_capacity)
            .finish_non_exhaustive()
    }
}

impl PolicyLoader {
    pub fn new(engine: PolicyEngine) -> Self {
        Self {
            engine,
            store_pool_capacity: DEFAULT_STORE_POOL_CAPACITY,
        }
    }

    pub fn with_store_pool_capacity(mut self, capacity: usize) -> Self {
        self.store_pool_capacity = capacity.max(1);
        self
    }

    pub fn engine(&self) -> &PolicyEngine {
        &self.engine
    }

    /// Verifies and loads a policy from a private byte buffer.
    pub fn load_from_bytes(
        &self,
        bytes: &[u8],
        config: &AutotuneWasmConfig,
        trust: &TrustStoreV1,
        now: DateTime<Utc>,
    ) -> Result<WasmPolicyBackend> {
        self.load_from_bytes_inner(bytes, config, trust, now, true)
    }

    pub(super) fn load_from_bytes_inner(
        &self,
        bytes: &[u8],
        config: &AutotuneWasmConfig,
        trust: &TrustStoreV1,
        now: DateTime<Utc>,
        self_check: bool,
    ) -> Result<WasmPolicyBackend> {
        let limits = PackageLimits::from_config(config);
        let package = PolicyPackage::parse(bytes, limits).map_err(|error| anyhow!(error))?;
        let verified = package.verify(trust, now).map_err(|error| anyhow!(error))?;
        validate_manifest(&verified.manifest, config)?;
        let component = self.engine.compile(package.digest, bytes)?;
        let mut backend = WasmPolicyBackend::from_verified(
            self.engine.clone(),
            component,
            verified.manifest,
            verified.digest,
            verified.signer_id,
            config,
            self.store_pool_capacity,
        )?;
        if self_check {
            backend.self_check()?;
        }
        Ok(backend)
    }

    /// Reads a policy into a private `Vec<u8>` before invoking
    /// [`Self::load_from_bytes`].
    pub fn load_from_path(
        &self,
        path: &Path,
        config: &AutotuneWasmConfig,
        trust: &TrustStoreV1,
        now: DateTime<Utc>,
    ) -> Result<WasmPolicyBackend> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        self.load_from_bytes(&bytes, config, trust, now)
    }

    /// Loads the builtin policy component embedded in this binary.
    ///
    /// Trust comes from the checked-in BLAKE3 sidecar (the committed
    /// component is unsigned; the sidecar digest is pinned), so the
    /// operator's `require_signature`/signer settings do not apply. The
    /// resource budgets of `config` still bound the component.
    pub fn load_builtin(&self, config: &AutotuneWasmConfig) -> Result<WasmPolicyBackend> {
        let mut config = config.clone();
        config.require_signature = false;
        let package = PolicyPackage::parse(BUILTIN_WASM_V1, PackageLimits::from_config(&config))
            .map_err(|error| anyhow!(error))?;
        let expected = super::super::signature::parse_digest(BUILTIN_WASM_BLAKE3_V1.trim())
            .context("parsing the checked-in builtin.wasm digest sidecar")?;
        ensure!(
            package.digest == expected,
            "embedded builtin.wasm does not match its digest sidecar"
        );
        let trust = TrustStoreV1::with_digest_pins([expected]);
        self.load_from_bytes(BUILTIN_WASM_V1, &config, &trust, Utc::now())
    }
}

fn validate_manifest(manifest: &PolicyManifestV1, config: &AutotuneWasmConfig) -> Result<()> {
    ensure!(
        manifest.abi_world == POLICY_ABI_WORLD_V1,
        "policy ABI world {:?} is not {:?}",
        manifest.abi_world,
        POLICY_ABI_WORLD_V1
    );
    ensure!(
        manifest.maximum_state_bytes as u64 <= config.maximum_state_bytes,
        "policy maximum_state_bytes {} exceeds host maximum {}",
        manifest.maximum_state_bytes,
        config.maximum_state_bytes
    );
    ensure!(
        manifest.requested_memory_bytes as u64 <= config.maximum_memory_bytes,
        "policy requested_memory_bytes {} exceeds host maximum {}",
        manifest.requested_memory_bytes,
        config.maximum_memory_bytes
    );
    if !manifest.state_schema_accepts.is_empty() {
        ensure!(
            manifest
                .state_schema_accepts
                .contains(&manifest.state_schema),
            "policy state_schema {} is not listed in state_schema_accepts",
            manifest.state_schema
        );
    }
    Ok(())
}
