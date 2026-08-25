use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::derp::{DerpPublicKey, DerpServer};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub network_id: String,
    pub identity_file: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind_addresses: Vec<SocketAddr>,
    /// IP prefixes that direct underlay paths must not use. Both the local and
    /// remote address of an IP path are covered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_underlay_prefixes: Vec<IpNet>,
    #[serde(
        default = "default_tun_mtu",
        skip_serializing_if = "is_default_tun_mtu"
    )]
    pub tun_mtu: u16,
    #[serde(
        default = "default_node_interface",
        skip_serializing_if = "is_default_node_interface"
    )]
    pub node_interface: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_addresses: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertised_prefixes: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_info: Option<NodeInfo>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub relay: RelayConfig,
    /// QUIC-visible traffic cover. Endpoint identity remains authenticated in
    /// V2 SessionHello and is never derived from these public names.
    #[serde(default, skip_serializing_if = "is_default")]
    pub cover: CoverConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,
    /// Pairwise transport contracts. Locators in this section are local-only
    /// and are never copied into the signed mesh directory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<LinkConfig>,
    /// Resolved static routes. New configurations keep these in the sibling
    /// routes.toml registry; deserializing this field remains migration-only.
    #[serde(default, skip_serializing)]
    pub route_origins: Vec<RouteOriginConfig>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub routing: RoutingConfig,
    /// Opportunistic peer discovery and bounded direct-mesh policy. Normal
    /// deployments only need the defaults; configured peers remain pinned.
    #[serde(default, skip_serializing_if = "is_default")]
    pub mesh: MeshConfig,
    /// Local authoritative DNS synthesized from the signed mesh directory.
    #[serde(default, skip_serializing_if = "is_default")]
    pub dns: DnsConfig,
    /// Slow-path adaptive control. The defaults require no operator tuning:
    /// the built-in policy observes in shadow mode and persists per-peer
    /// network memory.
    #[serde(default, skip_serializing_if = "is_default")]
    pub autotune: AutotuneConfig,
    /// Advanced bounds for automatic QUIC path migration. RTT, ACK/PTO and
    /// on-path challenge observations still select the live deadline inside
    /// these bounds; this section only exists so operations can change
    /// guardrails without rebuilding the binary.
    #[serde(default, skip_serializing_if = "is_default")]
    pub path_migration: PathMigrationConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathMigrationConfig {
    #[serde(default = "default_path_pto_threshold")]
    pub pto_threshold: u32,
    #[serde(default = "default_path_min_pto_silence_ms")]
    pub min_pto_silence_ms: u64,
    #[serde(default = "default_path_min_silence_ms")]
    pub min_silence_ms: u64,
    #[serde(default = "default_path_max_silence_ms")]
    pub max_silence_ms: u64,
    #[serde(default = "default_path_recovery_probation_ms")]
    pub recovery_probation_ms: u64,
    #[serde(default = "default_path_recovery_max_response_gap_ms")]
    pub recovery_max_response_gap_ms: u64,
    #[serde(default = "default_path_recovery_min_responses")]
    pub recovery_min_responses: u64,
    #[serde(default = "default_path_health_ttl_secs")]
    pub health_ttl_secs: u64,
    #[serde(default = "default_path_rtt_switch_margin_ms")]
    pub rtt_switch_margin_ms: u64,
    #[serde(default = "default_path_keep_alive_ms")]
    pub keep_alive_ms: u64,
    #[serde(default = "default_path_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
}

impl Default for PathMigrationConfig {
    fn default() -> Self {
        Self {
            pto_threshold: default_path_pto_threshold(),
            min_pto_silence_ms: default_path_min_pto_silence_ms(),
            min_silence_ms: default_path_min_silence_ms(),
            max_silence_ms: default_path_max_silence_ms(),
            recovery_probation_ms: default_path_recovery_probation_ms(),
            recovery_max_response_gap_ms: default_path_recovery_max_response_gap_ms(),
            recovery_min_responses: default_path_recovery_min_responses(),
            health_ttl_secs: default_path_health_ttl_secs(),
            rtt_switch_margin_ms: default_path_rtt_switch_margin_ms(),
            keep_alive_ms: default_path_keep_alive_ms(),
            idle_timeout_ms: default_path_idle_timeout_ms(),
        }
    }
}

impl PathMigrationConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.pto_threshold > 0,
            "path_migration.pto_threshold must be non-zero"
        );
        ensure!(
            self.min_pto_silence_ms > 0,
            "path_migration.min_pto_silence_ms must be non-zero"
        );
        ensure!(
            self.min_silence_ms > 0,
            "path_migration.min_silence_ms must be non-zero"
        );
        ensure!(
            self.min_silence_ms <= self.max_silence_ms,
            "path_migration.min_silence_ms must not exceed max_silence_ms"
        );
        ensure!(
            self.min_pto_silence_ms <= self.min_silence_ms,
            "path_migration.min_pto_silence_ms must not exceed min_silence_ms"
        );
        ensure!(
            self.recovery_probation_ms > 0,
            "path_migration.recovery_probation_ms must be non-zero"
        );
        ensure!(
            self.recovery_max_response_gap_ms > 0,
            "path_migration.recovery_max_response_gap_ms must be non-zero"
        );
        ensure!(
            self.recovery_min_responses > 0,
            "path_migration.recovery_min_responses must be non-zero"
        );
        ensure!(
            self.health_ttl_secs > 0,
            "path_migration.health_ttl_secs must be non-zero"
        );
        ensure!(
            self.keep_alive_ms > 0,
            "path_migration.keep_alive_ms must be non-zero"
        );
        ensure!(
            self.keep_alive_ms < self.idle_timeout_ms,
            "path_migration.keep_alive_ms must be less than idle_timeout_ms"
        );
        ensure!(
            self.idle_timeout_ms > self.max_silence_ms,
            "path_migration.idle_timeout_ms must exceed max_silence_ms"
        );
        ensure!(
            self.idle_timeout_ms > self.recovery_probation_ms,
            "path_migration.idle_timeout_ms must exceed recovery_probation_ms"
        );
        Ok(())
    }
}

const fn default_path_pto_threshold() -> u32 {
    4
}
const fn default_path_min_pto_silence_ms() -> u64 {
    250
}
const fn default_path_min_silence_ms() -> u64 {
    1_000
}
const fn default_path_max_silence_ms() -> u64 {
    5_000
}
const fn default_path_recovery_probation_ms() -> u64 {
    2_000
}
const fn default_path_recovery_max_response_gap_ms() -> u64 {
    2_000
}
const fn default_path_recovery_min_responses() -> u64 {
    3
}
const fn default_path_health_ttl_secs() -> u64 {
    300
}
const fn default_path_rtt_switch_margin_ms() -> u64 {
    5
}
const fn default_path_keep_alive_ms() -> u64 {
    250
}
const fn default_path_idle_timeout_ms() -> u64 {
    15_000
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutotuneMode {
    Off,
    #[default]
    Shadow,
    On,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutotuneObjective {
    #[default]
    Balanced,
    Throughput,
    Latency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutotuneConfig {
    #[serde(default, skip_serializing_if = "is_default")]
    pub mode: AutotuneMode,
    #[serde(default, skip_serializing_if = "is_default")]
    pub objective: AutotuneObjective,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub memory: bool,
    /// Policy backend selection with three layers of meaning:
    ///
    /// - `native`: an explicit selection of host-side conservative rules. It only uses the
    ///   deterministic `AutoTunerV2` propose rules, carries no learner and
    ///   never loads an external artifact.
    /// - `builtin` (default): the learner-backed in-process `CorePolicy`
    ///   constructed from the canonical `PolicySpecV1::builtin()`. It does
    ///   not initialize Wasmtime or load `builtin.wasm`.
    /// - an absolute `.wasm` path: an external policy component verified
    ///   against `[autotune.wasm]` (signers or digest pins).
    ///
    /// `builtin.wasm` remains a bit-exact guest fixture and a distributable
    /// template for an explicitly configured external component; it is not
    /// the daemon's default execution path. A rejected external component
    /// falls back to the in-process builtin core without preventing the
    /// dataplane from starting.
    ///
    /// External JSON policy artifacts were removed in Phase 6; a `.json`
    /// path is a configuration error.
    #[serde(
        default = "default_autotune_policy",
        skip_serializing_if = "is_builtin_policy"
    )]
    pub policy: String,
    /// Optional candidate evaluated without affecting the wire action. Must
    /// be an absolute `.wasm` path (JSON artifacts were removed in Phase 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_policy: Option<PathBuf>,
    /// WASM policy trust store, resource budget and state persistence. The
    /// whole section is part of the sealed configuration: signers, digest
    /// pins and policy paths are never writable by a guest.
    #[serde(default, skip_serializing_if = "is_default")]
    pub wasm: AutotuneWasmConfig,
}

impl Default for AutotuneConfig {
    fn default() -> Self {
        Self {
            mode: AutotuneMode::Shadow,
            objective: AutotuneObjective::Balanced,
            memory: true,
            policy: default_autotune_policy(),
            shadow_policy: None,
            wasm: AutotuneWasmConfig::default(),
        }
    }
}

/// `autotune.policy` value selecting explicit host-side conservative rules.
pub const AUTOTUNE_POLICY_NATIVE: &str = "native";
/// `autotune.policy` value selecting the default in-process `CorePolicy`.
pub const AUTOTUNE_POLICY_BUILTIN: &str = "builtin";

fn default_autotune_policy() -> String {
    AUTOTUNE_POLICY_BUILTIN.to_owned()
}

fn is_builtin_policy(value: &str) -> bool {
    value == AUTOTUNE_POLICY_BUILTIN
}

fn is_wasm_policy_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm"))
}

impl AutotuneConfig {
    /// True when `policy` or `shadow_policy` names an external `.wasm`
    /// component, i.e. when the WASM trust store actually gates loading.
    pub fn uses_wasm_artifact(&self) -> bool {
        let policy = Path::new(&self.policy);
        (policy.is_absolute() && is_wasm_policy_path(policy))
            || self
                .shadow_policy
                .as_deref()
                .is_some_and(is_wasm_policy_path)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.policy.trim().is_empty(),
            "autotune.policy cannot be empty"
        );
        let policy_path = Path::new(&self.policy);
        ensure!(
            self.policy == AUTOTUNE_POLICY_NATIVE
                || self.policy == AUTOTUNE_POLICY_BUILTIN
                || (policy_path.is_absolute() && is_wasm_policy_path(policy_path)),
            "autotune.policy must be native, builtin or an absolute .wasm path \
             (external JSON policy artifacts were removed; deploy a signed .wasm component)"
        );
        if let Some(path) = &self.shadow_policy {
            ensure!(
                path.is_absolute() && is_wasm_policy_path(path),
                "autotune.shadow_policy must be an absolute .wasm path \
                 (external JSON policy artifacts were removed; deploy a signed .wasm component)"
            );
        }
        self.wasm.validate(self.uses_wasm_artifact())
    }
}

/// Trust store, resource budget and state persistence for WASM policy
/// components. Defaults follow the documented initial budget; every field is
/// sealed together with the rest of the configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutotuneWasmConfig {
    /// Production default. When `false`, `.wasm` policies must instead match
    /// one of `digest_pins`; a module's self-reported key never counts as
    /// trust.
    #[serde(default = "default_true")]
    pub require_signature: bool,
    /// Upper bound on the component file size in bytes.
    #[serde(default = "default_wasm_maximum_module_bytes")]
    pub maximum_module_bytes: u64,
    /// Upper bound on guest linear memory in bytes.
    #[serde(default = "default_wasm_maximum_memory_bytes")]
    pub maximum_memory_bytes: u64,
    /// Upper bound on the opaque per-peer state blob in bytes.
    #[serde(default = "default_wasm_maximum_state_bytes")]
    pub maximum_state_bytes: u64,
    /// Wall-clock deadline for a single `decide` call.
    #[serde(default = "default_wasm_deadline_millis")]
    pub deadline_millis: u64,
    /// Minimum interval between periodic per-peer state flushes to disk.
    /// State is also flushed on module switch, peer disconnect and shutdown.
    #[serde(default = "default_wasm_state_flush_interval_secs")]
    pub state_flush_interval_secs: u64,
    /// Trusted signers. Several may coexist to rotate keys; revocation is
    /// deleting the entry and re-sealing the configuration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<AutotuneSignerConfig>,
    /// Development-mode alternative to signatures: exact `blake3:<hex>`
    /// digests of the accepted component prefixes. Only consulted when
    /// `require_signature = false`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub digest_pins: Vec<String>,
}

impl Default for AutotuneWasmConfig {
    fn default() -> Self {
        Self {
            require_signature: true,
            maximum_module_bytes: default_wasm_maximum_module_bytes(),
            maximum_memory_bytes: default_wasm_maximum_memory_bytes(),
            maximum_state_bytes: default_wasm_maximum_state_bytes(),
            deadline_millis: default_wasm_deadline_millis(),
            state_flush_interval_secs: default_wasm_state_flush_interval_secs(),
            signers: Vec::new(),
            digest_pins: Vec::new(),
        }
    }
}

/// One entry of the WASM policy trust store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutotuneSignerConfig {
    /// Operator-chosen identifier matched against the component signature
    /// section.
    pub signer_id: String,
    /// `ed25519:<key>` where the key is the 32-byte public key in hex (64
    /// characters) or RFC 4648 base32 (52 characters, optional `====`).
    pub public_key: String,
    /// Rollback floor: components signed by this signer are rejected when
    /// their `policy_version` is lower.
    #[serde(default)]
    pub minimum_policy_version: u64,
    /// Optional RFC 3339 expiry after which this signer is no longer trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

const WASM_MAXIMUM_STATE_BYTES_LIMIT: u64 = 1024 * 1024;
const WASM_DEADLINE_MILLIS_RANGE: std::ops::RangeInclusive<u64> = 1..=1000;

const fn default_wasm_maximum_module_bytes() -> u64 {
    8 * 1024 * 1024
}
const fn default_wasm_maximum_memory_bytes() -> u64 {
    8 * 1024 * 1024
}
const fn default_wasm_maximum_state_bytes() -> u64 {
    64 * 1024
}
const fn default_wasm_deadline_millis() -> u64 {
    10
}
const fn default_wasm_state_flush_interval_secs() -> u64 {
    60
}

impl AutotuneWasmConfig {
    fn validate(&self, uses_wasm_artifact: bool) -> Result<()> {
        ensure!(
            self.maximum_module_bytes > 0,
            "autotune.wasm.maximum_module_bytes must be non-zero"
        );
        ensure!(
            self.maximum_memory_bytes > 0,
            "autotune.wasm.maximum_memory_bytes must be non-zero"
        );
        ensure!(
            (1..=WASM_MAXIMUM_STATE_BYTES_LIMIT).contains(&self.maximum_state_bytes),
            "autotune.wasm.maximum_state_bytes must be between 1 and {WASM_MAXIMUM_STATE_BYTES_LIMIT} (1 MiB)"
        );
        ensure!(
            WASM_DEADLINE_MILLIS_RANGE.contains(&self.deadline_millis),
            "autotune.wasm.deadline_millis must be between {} and {}",
            WASM_DEADLINE_MILLIS_RANGE.start(),
            WASM_DEADLINE_MILLIS_RANGE.end()
        );
        ensure!(
            self.state_flush_interval_secs >= 1,
            "autotune.wasm.state_flush_interval_secs must be at least 1"
        );

        let mut signer_ids = HashSet::new();
        for signer in &self.signers {
            let signer_id = signer.signer_id.trim();
            ensure!(
                !signer_id.is_empty(),
                "autotune.wasm.signers: signer_id cannot be empty"
            );
            ensure!(
                signer_ids.insert(signer_id),
                "autotune.wasm.signers: duplicate signer_id {signer_id:?}"
            );
            validate_signer_public_key(signer_id, &signer.public_key)?;
            if let Some(expires_at) = signer.expires_at.as_deref() {
                chrono::DateTime::parse_from_rfc3339(expires_at).with_context(|| {
                    format!(
                        "autotune.wasm.signers[{signer_id}].expires_at must be an RFC 3339 timestamp, got {expires_at:?}"
                    )
                })?;
            }
        }

        for pin in &self.digest_pins {
            validate_digest_pin(pin)?;
        }

        if uses_wasm_artifact {
            if self.require_signature {
                ensure!(
                    !self.signers.is_empty(),
                    "autotune.wasm.require_signature = true with a .wasm policy requires at least one [[autotune.wasm.signers]] entry"
                );
            } else {
                ensure!(
                    !self.digest_pins.is_empty(),
                    "autotune.wasm.require_signature = false with a .wasm policy requires non-empty autotune.wasm.digest_pins"
                );
            }
        }
        Ok(())
    }
}

const ED25519_KEY_PREFIX: &str = "ed25519:";
const BLAKE3_PIN_PREFIX: &str = "blake3:";
/// 32 bytes in RFC 4648 base32 without padding.
const ED25519_BASE32_LEN: usize = 52;
const ED25519_HEX_LEN: usize = 64;
const BLAKE3_HEX_LEN: usize = 64;

fn is_hex_of_len(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_base32_ed25519_key(value: &str) -> bool {
    let unpadded = value.strip_suffix("====").unwrap_or(value);
    unpadded.len() == ED25519_BASE32_LEN
        && unpadded
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'2'..=b'7'))
}

fn validate_signer_public_key(signer_id: &str, public_key: &str) -> Result<()> {
    let Some(encoded) = public_key.strip_prefix(ED25519_KEY_PREFIX) else {
        bail!(
            "autotune.wasm.signers[{signer_id}].public_key must start with {ED25519_KEY_PREFIX:?}, got {public_key:?}"
        );
    };
    ensure!(
        is_hex_of_len(encoded, ED25519_HEX_LEN) || is_base32_ed25519_key(encoded),
        "autotune.wasm.signers[{signer_id}].public_key must be ed25519:<64 hex chars> or ed25519:<52 base32 chars> (32-byte key), got {public_key:?}"
    );
    Ok(())
}

fn validate_digest_pin(pin: &str) -> Result<()> {
    let Some(encoded) = pin.strip_prefix(BLAKE3_PIN_PREFIX) else {
        bail!(
            "autotune.wasm.digest_pins entries must start with {BLAKE3_PIN_PREFIX:?}, got {pin:?}"
        );
    };
    ensure!(
        is_hex_of_len(encoded, BLAKE3_HEX_LEN),
        "autotune.wasm.digest_pins entries must be blake3:<64 hex chars>, got {pin:?}"
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkConfig {
    pub name: String,
    pub peer_id: EndpointId,
    /// Private circuits are exclusive by default: path migration may not
    /// escape to discovery, relay, DERP or peer-observed public addresses.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub exclusive: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fallback: bool,
    /// Pairwise locators delivered by the private circuit. They are local
    /// configuration and never published through V2 Presence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_addresses: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Optional Tailscale DERP underlay transports. Direct UDP and V2 overlay
/// transit remain independent path choices.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Tailscale DERP transport servers. Each URL is one independent region.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,
}

impl RelayConfig {
    pub fn derp_enabled(&self) -> bool {
        !self.servers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverConfig {
    /// Network-level SNI pool. Selection is deterministic per peer and cover
    /// generation, while pool order has no semantic meaning.
    #[serde(default = "default_cover_sni_pool")]
    pub sni_pool: Vec<String>,
    #[serde(default = "default_cover_profile_id")]
    pub profile_id: u32,
}

impl Default for CoverConfig {
    fn default() -> Self {
        Self {
            sni_pool: default_cover_sni_pool(),
            profile_id: default_cover_profile_id(),
        }
    }
}

fn default_cover_sni_pool() -> Vec<String> {
    vec!["media.example".to_owned()]
}

const fn default_cover_profile_id() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub name: String,
    pub endpoint_id: EndpointId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_addresses: Vec<SocketAddr>,
    /// X25519 public key used to address this peer on DERP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_public_key: Option<DerpPublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOriginConfig {
    pub endpoint_id: EndpointId,
    pub prefixes: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub isolate_overlay: bool,
    /// Permit packets received from one Overlay Peer to be forwarded to
    /// another Overlay Peer. Peer-to-local-node and Peer-to-LAN forwarding is
    /// independent of this setting.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub transit_enabled: bool,
    #[serde(
        default = "default_rule_priority",
        skip_serializing_if = "is_default_rule_priority"
    )]
    pub rule_priority: u32,
    /// Dedicated Linux policy-routing table owned by V2 dataplane.
    #[serde(
        default = "default_routing_table",
        skip_serializing_if = "is_default_routing_table"
    )]
    pub table: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_default_routes: bool,
    /// Source-NAT packets arriving from the overlay before they are forwarded
    /// to a locally advertised LAN/service prefix. This removes the need for
    /// LAN hosts to carry explicit return routes for remote overlay prefixes.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub nat_enabled: bool,
    /// Optional local policy cap for this node's single overlay egress. This
    /// is never advertised to peers and is not a capacity measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_egress_mbps: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    /// Exchange signed node presence through authenticated peers and establish
    /// a bounded number of useful direct adjacencies.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// Hard limit for configured and automatically selected peer adjacencies
    /// combined. Presence records do not consume an adjacency slot.
    #[serde(
        default = "default_mesh_max_peers",
        skip_serializing_if = "is_default_mesh_max_peers"
    )]
    pub max_peers: usize,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_peers: default_mesh_max_peers(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// Serve the private zone from every attached node.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    /// Authoritative forward zone, without a trailing dot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Local high port advertised to systemd-resolved with SetLinkDNSEx.
    #[serde(
        default = "default_dns_listen_port",
        skip_serializing_if = "is_default_dns_listen_port"
    )]
    pub listen_port: u16,
    /// Add the private zone as a search domain for single-label lookups.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub short_names: bool,
    /// Install per-link split-DNS state in systemd-resolved.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub accept_dns: bool,
    /// Positive and negative answer TTL. Directory changes are still pushed
    /// immediately into the local authority; this bounds external stub caches.
    #[serde(
        default = "default_dns_ttl_secs",
        skip_serializing_if = "is_default_dns_ttl_secs"
    )]
    pub ttl_secs: u32,
    /// Overlay allocation pools used to route reverse lookups to this link.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reverse_prefixes: Vec<IpNet>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domain: None,
            listen_port: default_dns_listen_port(),
            short_names: true,
            accept_dns: true,
            ttl_secs: default_dns_ttl_secs(),
            reverse_prefixes: Vec::new(),
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            isolate_overlay: true,
            transit_enabled: true,
            rule_priority: default_rule_priority(),
            table: default_routing_table(),
            allow_default_routes: false,
            nat_enabled: true,
            max_egress_mbps: None,
        }
    }
}

impl RoutingConfig {
    pub fn max_egress_bps(&self) -> Option<u64> {
        self.max_egress_mbps
            .and_then(|value| value.checked_mul(1_000_000))
    }
}

impl Config {
    /// Returns the first configured node address for the requested address
    /// family. Configuration order is the stable selection rule when a node
    /// has more than one address in the same family.
    pub fn node_address(&self, is_ipv4: bool) -> Option<IpAddr> {
        self.node_addresses
            .iter()
            .map(IpNet::addr)
            .find(|address| address.is_ipv4() == is_ipv4)
    }

    pub async fn load(path: &Path) -> Result<Self> {
        Self::load_inner(path, true, None).await
    }

    pub async fn load_unsealed(path: &Path) -> Result<Self> {
        Self::load_inner(path, false, None).await
    }

    /// Load a sealed main configuration against an in-memory candidate route
    /// registry. Route CLI mutations use this before replacing routes.toml.
    pub async fn load_with_route_origins(
        path: &Path,
        route_origins: Vec<RouteOriginConfig>,
    ) -> Result<Self> {
        Self::load_inner(path, true, Some(route_origins)).await
    }

    async fn load_inner(
        path: &Path,
        sealed: bool,
        operator_candidate: Option<Vec<RouteOriginConfig>>,
    ) -> Result<Self> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        if sealed {
            verify_config_digest(path, raw.as_bytes()).await?;
        }
        let config = Self::decode(path, &raw)?;
        let route_sources = match operator_candidate {
            Some(candidate) => {
                crate::routes::RouteSources::load_with_operator_candidate(
                    &config.identity_file,
                    candidate,
                )
                .await?
            }
            None => crate::routes::RouteSources::load(&config.identity_file).await?,
        };
        route_sources.resolve_config(config)
    }

    /// Resolve the mutable route registry from a sealed main configuration
    /// without requiring the current registry contents to be valid.
    pub async fn route_registry_path_for(path: &Path) -> Result<PathBuf> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        verify_config_digest(path, raw.as_bytes()).await?;
        Ok(Self::decode(path, &raw)?.route_registry_path())
    }

    fn decode(path: &Path, raw: &str) -> Result<Self> {
        toml::from_str(raw).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn route_registry_path(&self) -> PathBuf {
        crate::routes::registry_path(&self.identity_file)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.network_id.trim().is_empty(),
            "network_id cannot be empty"
        );
        ensure!(self.tun_mtu >= 1280, "tun_mtu must be at least 1280");
        self.autotune.validate()?;
        self.path_migration.validate()?;
        validate_interface_name(&self.node_interface)?;
        ensure!(
            (2..32_766).contains(&self.routing.rule_priority),
            "routing.rule_priority must be between 2 and 32765"
        );
        ensure!(
            !matches!(self.routing.table, 0 | 253 | 254 | 255),
            "routing.table must be a non-reserved Linux routing table"
        );
        if let Some(max_egress_mbps) = self.routing.max_egress_mbps {
            ensure!(
                max_egress_mbps > 0,
                "routing.max_egress_mbps must be non-zero"
            );
            ensure!(
                max_egress_mbps.checked_mul(1_000_000).is_some(),
                "routing.max_egress_mbps is too large"
            );
        }
        ensure!(
            (1..=32).contains(&self.mesh.max_peers),
            "mesh.max_peers must be between 1 and 32"
        );
        ensure!(
            !self.mesh.enabled || self.peers.len() <= self.mesh.max_peers,
            "configured peers exceed mesh.max_peers"
        );
        ensure!(
            self.cover.profile_id != 0,
            "cover.profile_id zero is reserved"
        );
        ensure!(
            !self.cover.sni_pool.is_empty(),
            "cover.sni_pool cannot be empty"
        );
        let mut cover_names = HashSet::new();
        for name in &self.cover.sni_pool {
            crate::v2_runtime::validate_cover_sni(name)?;
            ensure!(cover_names.insert(name), "duplicate cover SNI {name}");
        }
        self.validate_bind_addresses()?;
        self.validate_node_info()?;
        self.validate_dns()?;

        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        let mut direct_addresses = HashSet::new();
        let mut derp_public_keys = HashSet::new();
        for peer in &self.peers {
            ensure!(!peer.name.trim().is_empty(), "peer name cannot be empty");
            ensure!(
                names.insert(&peer.name),
                "duplicate peer name {}",
                peer.name
            );
            ensure!(ids.insert(peer.endpoint_id), "duplicate peer endpoint_id");
            let private_link = self.link_for_peer(peer.endpoint_id).is_some();
            ensure!(
                !private_link
                    || (peer.direct_addresses.is_empty() && peer.derp_public_key.is_none()),
                "peer {} uses a private link and cannot also publish public/DERP locators",
                peer.name
            );
            if let Some(key) = peer.derp_public_key {
                ensure!(
                    derp_public_keys.insert(key),
                    "DERP public key {key} is assigned to multiple peers"
                );
            }
            for address in &peer.direct_addresses {
                ensure!(address.port() != 0, "peer {} has port zero", peer.name);
                if let Some(prefix) = self.excluded_underlay_prefix(address.ip()) {
                    bail!(
                        "peer {} direct address {address} is inside forbidden underlay prefix {prefix}",
                        peer.name
                    );
                }
                ensure!(
                    direct_addresses.insert(*address),
                    "direct address {address} is assigned to multiple peers"
                );
            }
        }

        self.validate_links(&ids)?;

        let mut origin_ids = HashSet::new();
        let mut owned_prefixes: Vec<(EndpointId, IpNet)> = Vec::new();
        for origin in &self.route_origins {
            ensure!(
                origin_ids.insert(origin.endpoint_id),
                "duplicate route origin endpoint_id {}",
                origin.endpoint_id
            );
            ensure!(
                !origin.prefixes.is_empty(),
                "route origin {} requires at least one prefix",
                origin.endpoint_id
            );
            for prefix in &origin.prefixes {
                validate_overlay_prefix(*prefix, self.routing.allow_default_routes)?;
                for (owner, existing) in &owned_prefixes {
                    ensure!(
                        *owner == origin.endpoint_id
                            || prefix.prefix_len() == 0
                            || existing.prefix_len() == 0
                            || !prefixes_overlap(*prefix, *existing),
                        "route origin prefix {prefix} overlaps {existing} owned by {owner}"
                    );
                }
                owned_prefixes.push((origin.endpoint_id, *prefix));
            }
        }

        for prefix in self.all_advertised_prefixes() {
            validate_overlay_prefix(prefix, self.routing.allow_default_routes)?;
            for (owner, remote) in &owned_prefixes {
                ensure!(
                    prefix.prefix_len() == 0
                        || remote.prefix_len() == 0
                        || !prefixes_overlap(prefix, *remote),
                    "local overlay prefix {prefix} overlaps remote prefix {remote} owned by {owner}"
                );
            }
        }

        let has_default_route = self
            .all_overlay_prefixes()
            .any(|prefix| prefix.prefix_len() == 0);
        if has_default_route {
            ensure!(
                self.routing.rule_priority > 1,
                "default routes require routing.rule_priority greater than one"
            );
            ensure!(
                !self.relay.derp_enabled(),
                "default routes require relay.servers to be empty"
            );
            ensure!(
                self.peers
                    .iter()
                    .all(|peer| !peer.direct_addresses.is_empty()
                        || self.link_for_peer(peer.endpoint_id).is_some()),
                "default routes require a static public or pairwise locator for every peer"
            );
        }

        for peer in &self.peers {
            for address in &peer.direct_addresses {
                ensure!(
                    !self
                        .all_overlay_prefixes()
                        .filter(|prefix| prefix.prefix_len() != 0)
                        .any(|prefix| prefix.contains(&address.ip())),
                    "peer {} direct address {} overlaps an overlay prefix",
                    peer.name,
                    address.ip()
                );
            }
        }

        self.validate_relay()?;
        Ok(())
    }

    fn validate_bind_addresses(&self) -> Result<()> {
        let mut forbidden_prefixes = HashSet::new();
        for prefix in &self.excluded_underlay_prefixes {
            ensure!(
                forbidden_prefixes.insert(*prefix),
                "duplicate excluded_underlay_prefixes entry {prefix}"
            );
        }

        ensure!(
            self.bind_addresses.len() <= 1,
            "V2 accepts one dual-stack bind address"
        );
        for address in &self.bind_addresses {
            if !address.ip().is_unspecified()
                && let Some(prefix) = self.excluded_underlay_prefix(address.ip())
            {
                bail!("bind address {address} is inside forbidden underlay prefix {prefix}");
            }
        }
        Ok(())
    }

    fn validate_node_info(&self) -> Result<()> {
        let Some(node_info) = &self.node_info else {
            return Ok(());
        };
        ensure!(
            !node_info.name.trim().is_empty(),
            "node_info.name cannot be empty"
        );
        ensure!(
            node_info.metadata.keys().all(|key| !key.trim().is_empty()),
            "node_info metadata keys cannot be empty"
        );
        ensure!(
            toml::to_string(node_info)?.len() <= 800,
            "encoded node_info cannot exceed 800 bytes"
        );
        Ok(())
    }

    fn validate_dns(&self) -> Result<()> {
        if !self.dns.enabled {
            ensure!(
                self.dns.domain.is_none() && self.dns.reverse_prefixes.is_empty(),
                "dns.domain and dns.reverse_prefixes require dns.enabled = true"
            );
            return Ok(());
        }
        ensure!(
            self.mesh.enabled,
            "dns.enabled requires mesh.enabled = true"
        );
        ensure!(
            !self.node_addresses.is_empty(),
            "dns.enabled requires at least one node_addresses entry"
        );
        ensure!(self.node_info.is_some(), "dns.enabled requires [node_info]");
        ensure!(self.dns.listen_port != 0, "dns.listen_port cannot be zero");
        ensure!(
            (1..=300).contains(&self.dns.ttl_secs),
            "dns.ttl_secs must be between 1 and 300"
        );
        let domain = self
            .dns
            .domain
            .as_deref()
            .context("dns.enabled requires dns.domain")?;
        validate_dns_domain(domain)?;
        let mut prefixes = HashSet::new();
        for prefix in &self.dns.reverse_prefixes {
            validate_overlay_prefix(*prefix, false)?;
            ensure!(
                prefixes.insert(*prefix),
                "duplicate dns.reverse_prefixes entry {prefix}"
            );
        }
        Ok(())
    }

    fn validate_links(&self, peer_ids: &HashSet<EndpointId>) -> Result<()> {
        let mut names = HashSet::new();
        let mut peers = HashSet::new();
        let mut remotes = HashSet::new();
        for link in &self.links {
            ensure!(!link.name.trim().is_empty(), "link name cannot be empty");
            ensure!(
                names.insert(&link.name),
                "duplicate link name {}",
                link.name
            );
            ensure!(
                peers.insert(link.peer_id),
                "peer {} has more than one link contract",
                link.peer_id
            );
            ensure!(
                peer_ids.contains(&link.peer_id),
                "link {} references an unknown peer",
                link.name
            );
            ensure!(
                link.exclusive,
                "private link {} must be exclusive",
                link.name
            );
            ensure!(
                !link.fallback,
                "private link {} cannot enable public fallback",
                link.name
            );
            ensure!(
                !link.remote_addresses.is_empty(),
                "private link {} requires remote_addresses",
                link.name
            );
            for remote in &link.remote_addresses {
                ensure!(
                    remote.port() != 0,
                    "link {} remote address has port zero",
                    link.name
                );
                ensure!(
                    remotes.insert(*remote),
                    "private remote address {remote} is assigned to multiple links"
                );
            }
        }
        Ok(())
    }

    pub fn link_for_peer(&self, peer_id: EndpointId) -> Option<&LinkConfig> {
        self.links.iter().find(|link| link.peer_id == peer_id)
    }

    pub fn static_underlay_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.peers
            .iter()
            .flat_map(|peer| peer.direct_addresses.iter().copied())
            .chain(
                self.links
                    .iter()
                    .flat_map(|link| link.remote_addresses.iter().copied()),
            )
    }

    pub fn endpoint_bind_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.bind_addresses.iter().copied()
    }

    fn validate_relay(&self) -> Result<()> {
        if !self.relay.derp_enabled() {
            return self.ensure_no_derp_peer_keys();
        }

        let mut urls = HashSet::new();
        let mut regions = HashSet::new();
        for value in &self.relay.servers {
            let server = DerpServer::parse(value)
                .with_context(|| format!("invalid DERP server URL {value}"))?;
            ensure!(
                urls.insert(server.url.clone()),
                "duplicate DERP server URL {}",
                server.url
            );
            ensure!(
                regions.insert(server.region_id),
                "DERP region ID collision for {}",
                server.url
            );
        }
        for peer in &self.peers {
            ensure!(
                peer.derp_public_key.is_some(),
                "peer {} requires derp_public_key when relay.servers is configured",
                peer.name
            );
        }
        Ok(())
    }

    fn ensure_no_derp_peer_keys(&self) -> Result<()> {
        for peer in &self.peers {
            ensure!(
                peer.derp_public_key.is_none(),
                "peer {} derp_public_key requires relay.servers",
                peer.name
            );
        }
        Ok(())
    }

    pub fn excluded_underlay_prefix(&self, address: IpAddr) -> Option<IpNet> {
        self.excluded_underlay_prefixes
            .iter()
            .copied()
            .find(|prefix| prefix.contains(&address))
    }

    pub fn validate_local_id(&self, local_id: EndpointId) -> Result<()> {
        if self.peers.iter().any(|peer| peer.endpoint_id == local_id) {
            bail!("peer list contains this node's own endpoint ID");
        }
        if self
            .route_origins
            .iter()
            .any(|origin| origin.endpoint_id == local_id)
        {
            bail!("static route registry contains this node's own endpoint ID");
        }
        Ok(())
    }

    pub fn all_advertised_prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.node_addresses
            .iter()
            .chain(&self.advertised_prefixes)
            .copied()
    }

    pub fn all_remote_prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.route_origins
            .iter()
            .flat_map(|origin| origin.prefixes.iter().copied())
    }

    pub fn all_overlay_prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.all_advertised_prefixes()
            .chain(self.all_remote_prefixes())
    }

    /// Whether Linux must forward packets from the V2 dataplane TUN to a local
    /// LAN/service interface. Overlay transit itself stays in userspace.
    pub fn requires_forwarding(&self) -> bool {
        !self.advertised_prefixes.is_empty()
    }

    pub fn derp_servers(&self) -> Result<Vec<DerpServer>> {
        self.relay
            .servers
            .iter()
            .map(|url| DerpServer::parse(url))
            .collect()
    }

    pub fn derp_identity_file(&self) -> PathBuf {
        let mut path = self.identity_file.as_os_str().to_os_string();
        path.push(".derp");
        PathBuf::from(path)
    }
}

pub fn config_digest_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".blake3");
    PathBuf::from(value)
}

async fn verify_config_digest(path: &Path, raw: &[u8]) -> Result<()> {
    let digest_path = config_digest_path(path);
    let expected = tokio::fs::read_to_string(&digest_path)
        .await
        .with_context(|| {
            format!(
                "missing configuration integrity file {}; run seal-config",
                digest_path.display()
            )
        })?;
    let actual = blake3::hash(raw).to_hex();
    ensure!(
        expected.trim() == actual.as_str(),
        "configuration integrity check failed for {}",
        path.display()
    );
    Ok(())
}

pub fn validate_interface_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "interface name cannot be empty");
    ensure!(
        name.len() <= 15,
        "Linux interface names are limited to 15 bytes"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "invalid Linux interface name: {name}"
    );
    Ok(())
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}

pub(crate) const DEFAULT_TUN_MTU: u16 = 32 * 1024;

fn default_tun_mtu() -> u16 {
    DEFAULT_TUN_MTU
}

fn is_default_tun_mtu(value: &u16) -> bool {
    *value == default_tun_mtu()
}

fn default_node_interface() -> String {
    "ironet0".into()
}

fn is_default_node_interface(value: &str) -> bool {
    value == default_node_interface()
}

fn default_routing_table() -> u32 {
    211
}

fn is_default_routing_table(value: &u32) -> bool {
    *value == default_routing_table()
}

fn default_rule_priority() -> u32 {
    10_000
}

fn is_default_rule_priority(value: &u32) -> bool {
    *value == default_rule_priority()
}

fn default_mesh_max_peers() -> usize {
    12
}

fn is_default_mesh_max_peers(value: &usize) -> bool {
    *value == default_mesh_max_peers()
}

pub const fn default_dns_listen_port() -> u16 {
    1053
}

fn is_default_dns_listen_port(value: &u16) -> bool {
    *value == default_dns_listen_port()
}

pub const fn default_dns_ttl_secs() -> u32 {
    5
}

fn is_default_dns_ttl_secs(value: &u32) -> bool {
    *value == default_dns_ttl_secs()
}

fn validate_overlay_prefix(prefix: IpNet, allow_default_routes: bool) -> Result<()> {
    ensure!(
        allow_default_routes || prefix.prefix_len() != 0,
        "default overlay route {prefix} requires routing.allow_default_routes = true"
    );
    let address = prefix.addr();
    ensure!(
        !address.is_loopback(),
        "loopback prefix {prefix} is not allowed"
    );
    ensure!(
        !address.is_multicast(),
        "multicast prefix {prefix} is not allowed"
    );
    ensure!(
        !address.is_unspecified() || prefix.prefix_len() == 0,
        "unspecified prefix {prefix} is not allowed"
    );
    if let std::net::IpAddr::V6(address) = address {
        ensure!(
            !address.is_unicast_link_local(),
            "link-local prefix {prefix} is not allowed"
        );
    }
    if let std::net::IpAddr::V4(address) = address {
        ensure!(
            !address.is_link_local(),
            "link-local prefix {prefix} is not allowed"
        );
    }
    Ok(())
}

fn validate_dns_domain(domain: &str) -> Result<()> {
    let domain = domain.trim_end_matches('.');
    ensure!(!domain.is_empty(), "dns.domain cannot be empty");
    ensure!(domain.len() <= 253, "dns.domain cannot exceed 253 bytes");
    ensure!(
        domain.split('.').count() >= 2,
        "dns.domain must contain at least two labels"
    );
    for label in domain.split('.') {
        ensure!(!label.is_empty(), "dns.domain contains an empty label");
        ensure!(label.len() <= 63, "dns.domain label exceeds 63 bytes");
        ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "dns.domain labels cannot start or end with '-'"
        );
        ensure!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "dns.domain labels may only contain letters, digits and '-'"
        );
    }
    Ok(())
}

fn prefixes_overlap(left: IpNet, right: IpNet) -> bool {
    left.addr().is_ipv4() == right.addr().is_ipv4()
        && (left.contains(&right.network()) || right.contains(&left.network()))
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use ironet_extension_sdk::{
        ApplyRoutesRequest, CONTROL_API_VERSION, DesiredRouteSpec, RouteApply,
    };

    use super::*;

    fn id(byte: u8) -> EndpointId {
        SecretKey::from_bytes(&[byte; 32]).public()
    }

    #[test]
    fn overlay_transit_is_enabled_by_default() {
        assert!(RoutingConfig::default().transit_enabled);
    }

    fn extension_state(endpoint_id: EndpointId, prefix: &str) -> crate::extensions::ExtensionState {
        crate::extensions::ExtensionState::new()
            .apply(
                &ApplyRoutesRequest {
                    routes: vec![RouteApply {
                        api_version: CONTROL_API_VERSION,
                        name: "office".into(),
                        owner: "example.com/ipam".into(),
                        revision: 1,
                        ttl_seconds: None,
                        spec: DesiredRouteSpec {
                            endpoint_id: endpoint_id.to_string(),
                            prefixes: vec![prefix.into()],
                        },
                    }],
                    dry_run: false,
                    idempotency_key: "config-route-sources-test".into(),
                },
                100,
            )
            .unwrap()
            .state
    }

    fn contains_route(config: &Config, prefix: &str, endpoint_id: EndpointId) -> bool {
        let prefix = prefix.parse::<IpNet>().unwrap();
        config
            .route_origins
            .iter()
            .any(|origin| origin.endpoint_id == endpoint_id && origin.prefixes.contains(&prefix))
    }

    #[test]
    fn minimal_v2_config_uses_automatic_dataplane_defaults() {
        let config: Config = toml::from_str(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"

[cover]
sni_pool = ["cdn.live.example"]
profile_id = 7
"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.tun_mtu, 32 * 1024);
        assert_eq!(config.node_interface, "ironet0");
        assert_eq!(config.cover.profile_id, 7);
        assert_eq!(config.autotune, AutotuneConfig::default());
        assert_eq!(config.path_migration, PathMigrationConfig::default());
    }

    #[test]
    fn documented_example_uses_the_default_tun_mtu() {
        let config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        assert_eq!(config.tun_mtu, DEFAULT_TUN_MTU);
    }

    #[test]
    fn path_migration_guardrails_are_runtime_configurable_and_validated() {
        let config: Config = toml::from_str(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"

[path_migration]
pto_threshold = 6
min_pto_silence_ms = 300
min_silence_ms = 1200
max_silence_ms = 7000
recovery_probation_ms = 2500
recovery_max_response_gap_ms = 1800
recovery_min_responses = 4
health_ttl_secs = 600
rtt_switch_margin_ms = 8
keep_alive_ms = 200
idle_timeout_ms = 20000
"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.path_migration.pto_threshold, 6);
        assert_eq!(config.path_migration.idle_timeout_ms, 20_000);

        let mut invalid = config;
        invalid.path_migration.idle_timeout_ms = 1_000;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn autotune_is_typed_strict_and_requires_absolute_artifact_paths() {
        let config: Config = toml::from_str(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"

[autotune]
mode = "on"
objective = "throughput"
memory = false
policy = "/etc/ironet/policy.v2.wasm"
shadow_policy = "/etc/ironet/policy.next.wasm"

[autotune.wasm]
require_signature = false
digest_pins = ["blake3:abababababababababababababababababababababababababababababababab"]
"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.autotune.mode, AutotuneMode::On);
        assert_eq!(config.autotune.objective, AutotuneObjective::Throughput);
        assert!(!config.autotune.memory);

        let mut invalid = config.clone();
        invalid.autotune.policy = "relative.wasm".to_owned();
        assert!(invalid.validate().is_err());

        let error = toml::from_str::<Config>(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"
[autotune]
manual_gain = 1.2
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn autotune_policy_accepts_native_builtin_and_signed_wasm_paths() {
        let mut config: Config = toml::from_str(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"

[autotune]
policy = "native"
"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.autotune.policy, AUTOTUNE_POLICY_NATIVE);
        assert!(!config.autotune.uses_wasm_artifact());

        config.autotune.policy = AUTOTUNE_POLICY_BUILTIN.to_owned();
        config.validate().unwrap();

        // External policies are `.wasm` components gated by the trust store.
        config.autotune.policy = "/etc/ironet/policy.wasm".to_owned();
        config.autotune.wasm.require_signature = false;
        config.autotune.wasm.digest_pins = vec![format!("blake3:{}", "ab".repeat(32))];
        config.validate().unwrap();

        // External JSON artifacts were removed in Phase 6: a clear migration
        // error, not a silent fallback.
        config.autotune.policy = "/etc/ironet/policy.json".to_owned();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("JSON"), "{error}");
        let mut shadow_json = config.clone();
        shadow_json.autotune.policy = AUTOTUNE_POLICY_BUILTIN.to_owned();
        shadow_json.autotune.shadow_policy = Some(PathBuf::from("/etc/ironet/next.json"));
        let error = shadow_json.validate().unwrap_err().to_string();
        assert!(error.contains("JSON"), "{error}");

        config.autotune.policy = "NATIVE".to_owned();
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("native, builtin or an absolute .wasm path"),
            "{error}"
        );
        config.autotune.policy = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn autotune_wasm_defaults_follow_documented_budget() {
        let config: Config = toml::from_str(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"
"#,
        )
        .unwrap();
        config.validate().unwrap();
        let wasm = &config.autotune.wasm;
        assert_eq!(*wasm, AutotuneWasmConfig::default());
        assert!(wasm.require_signature);
        assert_eq!(wasm.maximum_module_bytes, 8_388_608);
        assert_eq!(wasm.maximum_memory_bytes, 8_388_608);
        assert_eq!(wasm.maximum_state_bytes, 65_536);
        assert_eq!(wasm.deadline_millis, 10);
        assert_eq!(wasm.state_flush_interval_secs, 60);
        assert!(wasm.signers.is_empty());
        assert!(wasm.digest_pins.is_empty());
        // Defaults stay out of the serialized form so sealed files remain small.
        assert!(
            !toml::to_string(&config)
                .unwrap()
                .contains("[autotune.wasm]")
        );
    }

    const AUTOTUNE_WASM_EXAMPLE: &str = r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"

[autotune]
mode = "shadow"
objective = "balanced"
memory = true
policy = "/etc/ironet/policy.wasm"
shadow_policy = "/etc/ironet/policy.next.wasm"

[autotune.wasm]
require_signature = true
maximum_module_bytes = 8388608
maximum_memory_bytes = 8388608
maximum_state_bytes = 65536
deadline_millis = 10
state_flush_interval_secs = 60

[[autotune.wasm.signers]]
signer_id = "ops-2026"
public_key = "ed25519:AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"
minimum_policy_version = 3
expires_at = "2027-01-01T00:00:00Z"

[[autotune.wasm.signers]]
signer_id = "ops-2025"
public_key = "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#;

    fn wasm_example() -> Config {
        let config: Config = toml::from_str(AUTOTUNE_WASM_EXAMPLE).unwrap();
        config.validate().unwrap();
        config
    }

    #[test]
    fn autotune_wasm_full_example_parses_and_round_trips() {
        let config = wasm_example();
        assert!(config.autotune.uses_wasm_artifact());
        let wasm = &config.autotune.wasm;
        assert_eq!(wasm.signers.len(), 2);
        assert_eq!(wasm.signers[0].signer_id, "ops-2026");
        assert_eq!(wasm.signers[0].minimum_policy_version, 3);
        assert_eq!(
            wasm.signers[0].expires_at.as_deref(),
            Some("2027-01-01T00:00:00Z")
        );
        assert_eq!(wasm.signers[1].minimum_policy_version, 0);
        assert!(wasm.signers[1].expires_at.is_none());

        let encoded = toml::to_string(&config).unwrap();
        let decoded: Config = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.autotune, config.autotune);

        let error = toml::from_str::<Config>(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"
[autotune.wasm]
fuel = 1
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn autotune_wasm_unsigned_mode_requires_digest_pins_for_wasm_paths() {
        let mut config = wasm_example();
        config.autotune.wasm.require_signature = false;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("digest_pins"), "{error}");

        config.autotune.wasm.digest_pins = vec![format!("blake3:{}", "ab".repeat(32))];
        config.validate().unwrap();

        // JSON artifacts were removed: they no longer reach the trust-store
        // logic at all because the path itself is a migration error.
        let mut json = wasm_example();
        json.autotune.policy = "/etc/ironet/policy.json".to_owned();
        json.autotune.shadow_policy = None;
        assert!(json.validate().is_err());

        // A .wasm shadow policy alone is enough to require pins.
        let mut shadow_only = wasm_example();
        shadow_only.autotune.policy = AUTOTUNE_POLICY_BUILTIN.to_owned();
        shadow_only.autotune.wasm.require_signature = false;
        shadow_only.autotune.wasm.digest_pins = vec![format!("blake3:{}", "ab".repeat(32))];
        shadow_only.validate().unwrap();
        shadow_only.autotune.wasm.digest_pins.clear();
        assert!(shadow_only.validate().is_err());
    }

    #[test]
    fn autotune_wasm_signed_mode_requires_a_signer_for_wasm_paths() {
        let mut config = wasm_example();
        config.autotune.wasm.signers.clear();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("[[autotune.wasm.signers]]"), "{error}");
    }

    #[test]
    fn autotune_wasm_public_key_format_is_validated() {
        for bad in [
            "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ",
            "rsa:AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ",
            "ed25519:",
            "ed25519:abcd",
            "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
            "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefff",
            "ed25519:AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYP1",
        ] {
            let mut config = wasm_example();
            config.autotune.wasm.signers[0].public_key = bad.to_owned();
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("public_key"), "{bad}: {error}");
        }
        let mut config = wasm_example();
        config.autotune.wasm.signers[0].public_key =
            "ed25519:aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq====".to_owned();
        config.validate().unwrap();
    }

    #[test]
    fn autotune_wasm_digest_pin_format_is_validated() {
        for bad in ["", "blake3:", "sha256:abcd", "blake3:abcd"] {
            let mut config = wasm_example();
            config.autotune.wasm.digest_pins = vec![bad.to_owned()];
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("digest_pins"), "{bad}: {error}");
        }
        let mut config = wasm_example();
        config.autotune.wasm.digest_pins = vec![format!("blake3:{}", "Ab".repeat(32))];
        config.validate().unwrap();
    }

    #[test]
    fn autotune_wasm_deadline_is_bounded() {
        for bad in [0, 1001] {
            let mut config = wasm_example();
            config.autotune.wasm.deadline_millis = bad;
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("deadline_millis"), "{bad}: {error}");
        }
        for ok in [1, 1000] {
            let mut config = wasm_example();
            config.autotune.wasm.deadline_millis = ok;
            config.validate().unwrap();
        }
    }

    #[test]
    fn autotune_wasm_state_bytes_are_capped_at_one_mebibyte() {
        let mut config = wasm_example();
        config.autotune.wasm.maximum_state_bytes = 1024 * 1024 + 1;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("maximum_state_bytes"), "{error}");
        config.autotune.wasm.maximum_state_bytes = 1024 * 1024;
        config.validate().unwrap();
        config.autotune.wasm.maximum_state_bytes = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn autotune_wasm_flush_interval_must_be_positive() {
        let mut config = wasm_example();
        config.autotune.wasm.state_flush_interval_secs = 0;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("state_flush_interval_secs"), "{error}");
    }

    #[test]
    fn autotune_wasm_module_and_memory_budgets_must_be_non_zero() {
        let mut config = wasm_example();
        config.autotune.wasm.maximum_module_bytes = 0;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("maximum_module_bytes"), "{error}");
        let mut config = wasm_example();
        config.autotune.wasm.maximum_memory_bytes = 0;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("maximum_memory_bytes"), "{error}");
    }

    #[test]
    fn autotune_wasm_signer_ids_are_non_empty_and_unique() {
        let mut config = wasm_example();
        config.autotune.wasm.signers[1].signer_id = "  ".to_owned();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("signer_id cannot be empty"), "{error}");

        let mut config = wasm_example();
        config.autotune.wasm.signers[1].signer_id = "ops-2026".to_owned();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("duplicate signer_id"), "{error}");
    }

    #[test]
    fn autotune_wasm_signer_expiry_must_be_rfc3339() {
        let mut config = wasm_example();
        config.autotune.wasm.signers[0].expires_at = Some("2027-01-01".to_owned());
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("expires_at"), "{error}");
        config.autotune.wasm.signers[0].expires_at = Some("2027-01-01T00:00:00+08:00".to_owned());
        config.validate().unwrap();
    }

    #[test]
    fn removed_v1_tuning_field_is_rejected() {
        let error = toml::from_str::<Config>(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"
quic_send_buffer_bytes = 131072
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));

        let error = toml::from_str::<Config>(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"

[observability]
metrics_file = "/tmp/legacy.prom"
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn obsolete_underlay_key_is_rejected() {
        let error = toml::from_str::<Config>(
            r#"
network_id = "test-network"
identity_file = "/tmp/ironet-v2.key"
forbidden_underlay_prefixes = ["200::/7"]
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[tokio::test]
    async fn config_load_variants_keep_their_route_candidate_contracts() {
        let directory = tempfile::tempdir().unwrap();
        let identity_file = directory.path().join("identity.key");
        let config_path = directory.path().join("config.toml");
        let raw = format!(
            "network_id = \"route-sources\"\nidentity_file = \"{}\"\n",
            identity_file.display()
        );
        std::fs::write(&config_path, &raw).unwrap();
        std::fs::write(
            config_digest_path(&config_path),
            blake3::hash(raw.as_bytes()).to_hex().to_string(),
        )
        .unwrap();

        let disk_operator = id(20);
        let extension_owner = id(21);
        let candidate_operator = id(22);
        crate::routes::RouteRegistry::parse_lines(&format!("{disk_operator} 10.20.0.0/24\n"))
            .unwrap()
            .write(&crate::routes::registry_path(&identity_file))
            .unwrap();
        extension_state(extension_owner, "10.21.0.0/24")
            .write(&crate::extensions::state_path(&identity_file))
            .unwrap();

        let unsealed = Config::load_unsealed(&config_path).await.unwrap();
        assert!(contains_route(&unsealed, "10.20.0.0/24", disk_operator));
        assert!(contains_route(&unsealed, "10.21.0.0/24", extension_owner));

        let sealed = Config::load(&config_path).await.unwrap();
        assert!(contains_route(&sealed, "10.20.0.0/24", disk_operator));
        assert!(contains_route(&sealed, "10.21.0.0/24", extension_owner));

        let candidate = Config::load_with_route_origins(
            &config_path,
            vec![RouteOriginConfig {
                endpoint_id: candidate_operator,
                prefixes: vec!["10.22.0.0/24".parse().unwrap()],
            }],
        )
        .await
        .unwrap();
        assert!(contains_route(
            &candidate,
            "10.22.0.0/24",
            candidate_operator
        ));
        assert!(contains_route(&candidate, "10.21.0.0/24", extension_owner));
        assert!(!contains_route(&candidate, "10.20.0.0/24", disk_operator));
    }
}
