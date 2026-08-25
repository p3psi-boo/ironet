use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, RouteOriginConfig},
    deployment,
    extensions::{self, ExtensionState},
    identity,
};

const ROUTE_FILE_VERSION: u8 = 1;

/// CLI-managed static route registry. It intentionally lives outside the
/// sealed daemon configuration so route changes do not rewrite config.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRegistry {
    #[serde(default = "route_file_version")]
    pub version: u8,
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteOriginConfig>,
}

impl Default for RouteRegistry {
    fn default() -> Self {
        Self {
            version: ROUTE_FILE_VERSION,
            routes: Vec::new(),
        }
    }
}

impl RouteRegistry {
    pub async fn load(path: &Path) -> Result<Self> {
        match tokio::fs::read_to_string(path).await {
            Ok(raw) => Self::parse(&raw)
                .with_context(|| format!("failed to parse route registry {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error)
                .with_context(|| format!("failed to read route registry {}", path.display())),
        }
    }

    pub async fn import(path: &Path) -> Result<Self> {
        let raw = if path == Path::new("-") {
            let mut raw = String::new();
            std::io::stdin()
                .read_to_string(&mut raw)
                .context("failed to read route import from standard input")?;
            raw
        } else {
            tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("failed to read route import {}", path.display()))?
        };
        let source = if path == Path::new("-") {
            "standard input".into()
        } else {
            path.display().to_string()
        };
        Self::parse(&raw).or_else(|toml_error| {
            Self::parse_lines(&raw).with_context(|| {
                format!(
                    "failed to parse {source} as routes TOML ({toml_error}) or line-oriented routes"
                )
            })
        })
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let mut registry: Self = toml::from_str(raw)?;
        registry.normalize()?;
        Ok(registry)
    }

    /// Parse one owner and one or more prefixes per line:
    /// `<endpoint-id> <prefix> [prefix ...]`. Blank lines and `#` comments are
    /// ignored, making small route inventories convenient to generate.
    pub fn parse_lines(raw: &str) -> Result<Self> {
        let mut routes = Vec::new();
        for (index, original) in raw.lines().enumerate() {
            let line = original.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let endpoint_id = fields
                .next()
                .context("missing endpoint ID")?
                .parse::<EndpointId>()
                .with_context(|| format!("line {} has an invalid endpoint ID", index + 1))?;
            let prefixes = fields
                .map(|value| {
                    value
                        .parse::<IpNet>()
                        .with_context(|| format!("line {} has invalid prefix {value}", index + 1))
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                !prefixes.is_empty(),
                "line {} requires at least one prefix",
                index + 1
            );
            routes.push(RouteOriginConfig {
                endpoint_id,
                prefixes,
            });
        }
        let mut registry = Self {
            version: ROUTE_FILE_VERSION,
            routes,
        };
        registry.normalize()?;
        Ok(registry)
    }

    pub fn merge(&mut self, imported: Self) -> Result<()> {
        self.routes.extend(imported.routes);
        self.normalize()
    }

    pub fn remove(&mut self, selector: &str) -> Result<usize> {
        if let Ok(prefix) = selector.parse::<IpNet>() {
            let before = self.prefix_count();
            for route in &mut self.routes {
                route.prefixes.retain(|candidate| *candidate != prefix);
            }
            self.routes.retain(|route| !route.prefixes.is_empty());
            return Ok(before - self.prefix_count());
        }
        if let Ok(endpoint_id) = EndpointId::from_str(selector) {
            let before = self.prefix_count();
            self.routes.retain(|route| route.endpoint_id != endpoint_id);
            return Ok(before - self.prefix_count());
        }
        bail!("route selector must be a prefix or endpoint ID: {selector}")
    }

    pub fn prefix_count(&self) -> usize {
        self.routes.iter().map(|route| route.prefixes.len()).sum()
    }

    pub fn flattened(&self) -> Vec<(IpNet, EndpointId)> {
        let mut entries = self
            .routes
            .iter()
            .flat_map(|route| {
                route
                    .prefixes
                    .iter()
                    .copied()
                    .map(|prefix| (prefix, route.endpoint_id))
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.0
                .to_string()
                .cmp(&right.0.to_string())
                .then_with(|| left.1.to_string().cmp(&right.1.to_string()))
        });
        entries
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let encoded = toml::to_string_pretty(self)?;
        // The state directory is private; the registry itself is intentionally
        // readable by the unprivileged daemon after a root CLI atomically
        // replaces it.
        deployment::atomic_write(path, encoded.as_bytes(), 0o644)
    }

    pub fn normalize(&mut self) -> Result<()> {
        ensure!(
            self.version == ROUTE_FILE_VERSION,
            "unsupported route registry version {}; expected {ROUTE_FILE_VERSION}",
            self.version
        );
        let mut owners: BTreeMap<String, (EndpointId, Vec<IpNet>)> = BTreeMap::new();
        for route in self.routes.drain(..) {
            ensure!(
                !route.prefixes.is_empty(),
                "route owner {} requires at least one prefix",
                route.endpoint_id
            );
            owners
                .entry(route.endpoint_id.to_string())
                .or_insert_with(|| (route.endpoint_id, Vec::new()))
                .1
                .extend(route.prefixes);
        }

        self.routes = owners
            .into_values()
            .map(|(endpoint_id, mut prefixes)| {
                let mut seen = HashSet::new();
                prefixes.retain(|prefix| seen.insert(*prefix));
                prefixes.sort_by_key(ToString::to_string);
                RouteOriginConfig {
                    endpoint_id,
                    prefixes,
                }
            })
            .collect();
        Ok(())
    }
}

/// The two durable sources that contribute remote routes at runtime.
///
/// `routes.toml` is operator-owned static state, while `extensions.toml` is
/// revisioned and lease-backed extension state. They retain their independent
/// on-disk formats; this facade is the only place that turns them into the
/// single normalized route model consumed by a [`Config`].
#[derive(Debug, Clone)]
pub(crate) struct RouteSources {
    operator: RouteRegistry,
    extensions: ExtensionState,
    now_unix: u64,
}

impl RouteSources {
    /// Load both durable route sources for a node identity.
    pub(crate) async fn load(identity_file: &Path) -> Result<Self> {
        let operator_path = registry_path(identity_file);
        let extension_path = extensions::state_path(identity_file);
        let (operator, extension_state) = tokio::try_join!(
            RouteRegistry::load(&operator_path),
            ExtensionState::load(&extension_path),
        )?;
        Ok(Self::from_parts(
            operator,
            extension_state,
            extensions::now_unix(),
        ))
    }

    /// Use an in-memory operator-route candidate while loading the current
    /// extension state. Route CLI mutations use this before replacing
    /// `routes.toml`.
    pub(crate) async fn load_with_operator_candidate(
        identity_file: &Path,
        operator_routes: Vec<RouteOriginConfig>,
    ) -> Result<Self> {
        let extension_state = ExtensionState::load(&extensions::state_path(identity_file)).await?;
        Ok(Self::from_parts(
            RouteRegistry {
                version: ROUTE_FILE_VERSION,
                routes: operator_routes,
            },
            extension_state,
            extensions::now_unix(),
        ))
    }

    /// Use an in-memory extension-state candidate while loading the current
    /// operator route registry. Control mutations use this before writing
    /// `extensions.toml`.
    pub(crate) async fn load_with_extension_candidate(
        identity_file: &Path,
        extension_state: ExtensionState,
    ) -> Result<Self> {
        let operator = RouteRegistry::load(&registry_path(identity_file)).await?;
        Ok(Self::from_parts(
            operator,
            extension_state,
            extensions::now_unix(),
        ))
    }

    /// Build a source set from already-loaded state. The explicit clock keeps
    /// candidate validation and TTL resolution deterministic for one pass.
    fn from_parts(operator: RouteRegistry, extension_state: ExtensionState, now_unix: u64) -> Self {
        Self {
            operator,
            extensions: extension_state,
            now_unix,
        }
    }

    /// Normalize and merge operator and active extension routes.
    fn compose(&self) -> Result<RouteRegistry> {
        let mut routes = self.operator.clone();
        routes
            .routes
            .extend(self.extensions.route_origins(self.now_unix)?);
        routes.normalize()?;
        Ok(routes)
    }

    /// Compose the dynamic sources with migration-only routes embedded in a
    /// main config. Embedded routes retain their previous behavior when both
    /// durable sources are empty.
    fn compose_with_embedded(
        &self,
        embedded_routes: Vec<RouteOriginConfig>,
    ) -> Result<Vec<RouteOriginConfig>> {
        let dynamic_routes = self.compose()?;
        if dynamic_routes.routes.is_empty() {
            return Ok(embedded_routes);
        }

        let mut combined = RouteRegistry {
            version: ROUTE_FILE_VERSION,
            routes: embedded_routes,
        };
        combined.merge(dynamic_routes)?;
        Ok(combined.routes)
    }

    /// Resolve a decoded main configuration into the single runtime route
    /// model and validate the resulting configuration.
    pub(crate) fn resolve_config(&self, mut config: Config) -> Result<Config> {
        config.route_origins =
            self.compose_with_embedded(std::mem::take(&mut config.route_origins))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate a candidate source set against an already-resolved runtime
    /// config. Its current `route_origins` are dynamic output from an earlier
    /// load, so the candidate replaces them instead of merging them again.
    pub(crate) fn validate_candidate(&self, config: &Config) -> Result<()> {
        let mut candidate = config.clone();
        candidate.route_origins = self.compose()?.routes;
        candidate.validate()
    }
}

/// Keep mutable routes with the node identity under the state directory. This
/// works for ordinary packages and immutable Nix-store main configurations
/// without adding another main-configuration setting.
pub fn registry_path(identity_file: &Path) -> PathBuf {
    identity_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("routes.toml")
}

pub async fn validate_for_config(config_path: &Path, registry: &RouteRegistry) -> Result<()> {
    let config = Config::load_with_route_origins(config_path, registry.routes.clone()).await?;
    let secret_key = identity::load_or_create(&config.identity_file)?;
    config.validate_local_id(secret_key.public())
}

fn route_file_version() -> u8 {
    ROUTE_FILE_VERSION
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

    fn extension_state(
        endpoint_id: EndpointId,
        prefix: &str,
        ttl_seconds: Option<u64>,
    ) -> ExtensionState {
        ExtensionState::new()
            .apply(
                &ApplyRoutesRequest {
                    routes: vec![RouteApply {
                        api_version: CONTROL_API_VERSION,
                        name: "office".into(),
                        owner: "example.com/ipam".into(),
                        revision: 1,
                        ttl_seconds,
                        spec: DesiredRouteSpec {
                            endpoint_id: endpoint_id.to_string(),
                            prefixes: vec![prefix.into()],
                        },
                    }],
                    dry_run: false,
                    idempotency_key: "route-sources-test".into(),
                },
                100,
            )
            .unwrap()
            .state
    }

    #[test]
    fn line_import_groups_owners_and_deduplicates_prefixes() {
        let first = id(1);
        let second = id(2);
        let registry = RouteRegistry::parse_lines(&format!(
            "# generated\n{first} 10.0.0.0/24 10.0.1.0/24\n{first} 10.0.0.0/24\n{second} 10.0.2.0/24\n"
        ))
        .unwrap();
        assert_eq!(registry.routes.len(), 2);
        assert_eq!(registry.prefix_count(), 3);
    }

    #[test]
    fn selector_removes_a_prefix_or_an_owner() {
        let first = id(3);
        let second = id(4);
        let mut registry = RouteRegistry::parse_lines(&format!(
            "{first} 10.1.0.0/24 10.1.1.0/24\n{second} 10.2.0.0/24\n"
        ))
        .unwrap();
        assert_eq!(registry.remove("10.1.0.0/24").unwrap(), 1);
        assert_eq!(registry.remove(&second.to_string()).unwrap(), 1);
        assert_eq!(registry.prefix_count(), 1);
    }

    #[test]
    fn canonical_toml_round_trips() {
        let registry = RouteRegistry::parse_lines(&format!("{} 10.3.0.0/16\n", id(5))).unwrap();
        let encoded = toml::to_string_pretty(&registry).unwrap();
        assert_eq!(RouteRegistry::parse(&encoded).unwrap().prefix_count(), 1);
        assert!(encoded.contains("[[route]]"));
    }

    #[test]
    fn route_sources_merge_operator_and_active_extension_routes() {
        let operator_id = id(6);
        let extension_id = id(7);
        let operator = RouteRegistry::parse_lines(&format!("{operator_id} 10.4.0.0/24\n")).unwrap();
        let extension = extension_state(extension_id, "10.5.0.0/24", Some(300));
        let sources = RouteSources::from_parts(operator, extension, 200);

        let routes = sources.compose().unwrap();
        assert_eq!(
            routes.flattened(),
            vec![
                ("10.4.0.0/24".parse().unwrap(), operator_id),
                ("10.5.0.0/24".parse().unwrap(), extension_id),
            ]
        );
    }

    #[test]
    fn route_sources_apply_extension_ttl_during_composition() {
        let operator_id = id(8);
        let extension_id = id(9);
        let operator = RouteRegistry::parse_lines(&format!("{operator_id} 10.6.0.0/24\n")).unwrap();
        let extension = extension_state(extension_id, "10.7.0.0/24", Some(1));

        let routes = RouteSources::from_parts(operator, extension, 101)
            .compose()
            .unwrap();
        assert_eq!(
            routes.flattened(),
            vec![("10.6.0.0/24".parse().unwrap(), operator_id)]
        );
    }
}
