//! Linux host networking and overlay address setup for the V2 runtime.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use iroh::EndpointId;
use tracing::{info, warn};

use super::{TUN_REGULAR_INPUT_BYTES, V2RuntimeConfig};

// Linux gives fq_codel on a TUN a 32 MiB memory limit by default. Once the
// userspace reader applies backpressure that can retain seconds of stale
// inner-TCP data and strand FIN/control payloads behind it. Keep the kernel
// queue close to the userspace merge window; fq_codel still owns per-flow
// fairness, ECN marking and overload drops. This is deliberately derived from
// the bounded userspace merge window rather than becoming an independent queue.
const TUN_FQ_CODEL_MEMORY_BYTES: usize = TUN_REGULAR_INPUT_BYTES * 2;
const TUN_FQ_CODEL_PACKET_LIMIT: usize = 1024;
const V2_NAT_INGRESS_CHAINS: [&str; 2] = ["IRONET_V2_NAT_IN_A", "IRONET_V2_NAT_IN_B"];
const V2_NAT_EGRESS_CHAINS: [&str; 2] = ["IRONET_V2_NAT_OUT_A", "IRONET_V2_NAT_OUT_B"];
const LEGACY_V2_NAT_INGRESS_CHAIN: &str = "IRONET_V2_NAT_IN";
const LEGACY_V2_NAT_EGRESS_CHAIN: &str = "IRONET_V2_NAT_OUT";
const V2_NAT_CONNMARK: &str = "0x20000000/0x20000000";
// Private route-protocol marker used only for V2 dataplane-owned kernel
// routes. This mirrors `system.rs`; keeping the marker on every route makes
// crash recovery surgical instead of flushing an operator-owned table.
const V2_ROUTE_PROTOCOL: &str = "100";

#[derive(Debug, Clone)]
pub(super) struct KernelRoutePolicyV2 {
    tun_name: String,
    isolate_overlay: bool,
    table: u32,
    rule_priority: u32,
    underlay_addresses: Vec<IpAddr>,
    ipv4_source: Option<Ipv4Addr>,
    ipv6_source: Option<Ipv6Addr>,
}

impl KernelRoutePolicyV2 {
    fn from_config(config: &V2RuntimeConfig, local_v4: Ipv4Addr, local_v6: Ipv6Addr) -> Self {
        let mut underlay_addresses = config
            .mesh_peers
            .iter()
            .flat_map(|peer| peer.addresses.iter())
            .map(|address| address.ip())
            .filter(|address| !address.is_unspecified())
            .collect::<Vec<_>>();
        underlay_addresses.sort_unstable();
        underlay_addresses.dedup();
        Self {
            tun_name: config.tun_name.clone(),
            isolate_overlay: config.isolate_overlay,
            table: if config.isolate_overlay {
                config.routing_table
            } else {
                254
            },
            rule_priority: config.routing_rule_priority,
            underlay_addresses,
            ipv4_source: Some(local_v4),
            ipv6_source: Some(local_v6),
        }
    }

    fn install_policy(&self) -> Result<()> {
        if !self.isolate_overlay {
            return Ok(());
        }
        let priority = self.rule_priority.to_string();
        let table = self.table.to_string();
        for family in ["-4", "-6"] {
            remove_ip_rule(family, self.rule_priority, self.table, None)?;
            run_ip([
                family, "rule", "add", "priority", &priority, "lookup", &table, "protocol",
                "static",
            ])?;
        }
        let underlay_priority = self.rule_priority.saturating_sub(1);
        let underlay_priority_text = underlay_priority.to_string();
        for address in &self.underlay_addresses {
            let family = if address.is_ipv4() { "-4" } else { "-6" };
            let prefix = host_prefix_v2(*address);
            remove_ip_rule(family, underlay_priority, 254, Some(&prefix))?;
            run_ip([
                family,
                "rule",
                "add",
                "priority",
                &underlay_priority_text,
                "to",
                &prefix,
                "lookup",
                "main",
                "protocol",
                "static",
            ])?;
        }
        Ok(())
    }

    pub(super) fn replace_route(&self, prefix: IpNet) -> Result<()> {
        let family = if prefix.addr().is_ipv4() { "-4" } else { "-6" };
        let table = self.table.to_string();
        let prefix = prefix.to_string();
        let source = if family == "-4" {
            self.ipv4_source.map(|address| address.to_string())
        } else {
            self.ipv6_source.map(|address| address.to_string())
        };
        let mut arguments = vec![
            family.to_owned(),
            "route".to_owned(),
            "replace".to_owned(),
            "table".to_owned(),
            table,
            prefix,
            "dev".to_owned(),
            self.tun_name.clone(),
            "proto".to_owned(),
            V2_ROUTE_PROTOCOL.to_owned(),
        ];
        if let Some(source) = source {
            arguments.extend(["src".to_owned(), source]);
        }
        run_ip_vec(&arguments)
    }

    pub(super) fn delete_route(&self, prefix: IpNet) -> Result<()> {
        let family = if prefix.addr().is_ipv4() { "-4" } else { "-6" };
        let table = self.table.to_string();
        let prefix = prefix.to_string();
        run_ip_allow_failure([
            family,
            "route",
            "del",
            "table",
            &table,
            &prefix,
            "proto",
            V2_ROUTE_PROTOCOL,
        ])
    }

    fn cleanup(&self) -> Result<()> {
        let table = self.table.to_string();
        for family in ["-4", "-6"] {
            run_ip_allow_failure([
                family,
                "route",
                "flush",
                "table",
                &table,
                "proto",
                V2_ROUTE_PROTOCOL,
            ])?;
        }
        if self.isolate_overlay {
            for family in ["-4", "-6"] {
                remove_ip_rule(family, self.rule_priority, self.table, None)?;
            }
            let underlay_priority = self.rule_priority.saturating_sub(1);
            for address in &self.underlay_addresses {
                let family = if address.is_ipv4() { "-4" } else { "-6" };
                let prefix = host_prefix_v2(*address);
                remove_ip_rule(family, underlay_priority, 254, Some(&prefix))?;
            }
        }
        Ok(())
    }
}

/// Synchronous cleanup is intentional: `Drop` also runs on setup errors and
/// aborted Tokio tasks, so no async lifecycle gap can leave a policy rule
/// pointing at a stale overlay table.
pub(super) struct KernelRouteGuardV2(KernelRoutePolicyV2);

impl Drop for KernelRouteGuardV2 {
    fn drop(&mut self) {
        if let Err(error) = self.0.cleanup() {
            warn!(%error, "failed cleaning V2 kernel route policy");
        }
    }
}

pub fn derived_overlay_address(network_id: &str, endpoint_id: EndpointId) -> Ipv6Addr {
    let mut input = Vec::with_capacity(network_id.len() + endpoint_id.as_bytes().len());
    input.extend_from_slice(network_id.as_bytes());
    input.extend_from_slice(endpoint_id.as_bytes());
    let digest = blake3::hash(&input);
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&digest.as_bytes()[..16]);
    octets[0] = 0xfd;
    Ipv6Addr::from(octets)
}

/// Derives a stable per-network endpoint address from the RFC 6598 shared
/// address space. A /32 is installed, so no L2/broadcast semantics apply.
pub fn derived_overlay_ipv4_address(network_id: &str, endpoint_id: EndpointId) -> Ipv4Addr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v2-overlay-ipv4");
    hasher.update(&(network_id.len() as u64).to_be_bytes());
    hasher.update(network_id.as_bytes());
    hasher.update(endpoint_id.as_bytes());
    let digest = hasher.finalize();
    let host = u32::from_be_bytes(digest.as_bytes()[..4].try_into().unwrap()) & 0x003f_ffff;
    Ipv4Addr::from(0x6440_0000 | host)
}

pub(super) fn local_overlay_addresses(
    config: &V2RuntimeConfig,
    endpoint_id: EndpointId,
) -> (Ipv4Addr, Ipv6Addr) {
    let ipv4 = config
        .node_addresses
        .iter()
        .find_map(|address| match address.addr() {
            std::net::IpAddr::V4(address) => Some(address),
            std::net::IpAddr::V6(_) => None,
        })
        .unwrap_or_else(|| derived_overlay_ipv4_address(&config.network_id, endpoint_id));
    let ipv6 = config
        .node_addresses
        .iter()
        .find_map(|address| match address.addr() {
            std::net::IpAddr::V6(address) => Some(address),
            std::net::IpAddr::V4(_) => None,
        })
        .unwrap_or_else(|| derived_overlay_address(&config.network_id, endpoint_id));
    (ipv4, ipv6)
}

pub(super) fn configure_mesh_tunnel(
    config: &V2RuntimeConfig,
    local_v4: Ipv4Addr,
    local_v6: Ipv6Addr,
) -> Result<(Arc<KernelRoutePolicyV2>, KernelRouteGuardV2)> {
    let policy = KernelRoutePolicyV2::from_config(config, local_v4, local_v6);
    policy.cleanup()?;
    let guard = KernelRouteGuardV2(policy.clone());
    run_ip(["link", "set", "dev", &config.tun_name, "up"])?;
    configure_tun_egress_aqm(&config.tun_name)?;
    run_ip([
        "-4",
        "address",
        "replace",
        &format!("{local_v4}/32"),
        "dev",
        &config.tun_name,
    ])?;
    run_ip([
        "-6",
        "address",
        "replace",
        &format!("{local_v6}/128"),
        "dev",
        &config.tun_name,
    ])?;
    policy.install_policy()?;
    for route in &config.routes {
        policy.replace_route(*route)?;
    }
    let policy = Arc::new(policy);
    Ok((policy, guard))
}

pub(super) fn reconcile_v2_nat(tun_name: &str, prefixes: &[IpNet], enabled: bool) -> Result<()> {
    let ipv4 = prefixes.iter().any(|prefix| prefix.addr().is_ipv4());
    let ipv6 = prefixes.iter().any(|prefix| prefix.addr().is_ipv6());
    if ipv4 {
        set_forwarding("net.ipv4.ip_forward")?;
    }
    if ipv6 {
        set_forwarding("net.ipv6.conf.all.forwarding")?;
    }
    if !enabled || prefixes.is_empty() {
        // Pure-routing nodes must not require firewall tooling. Only touch a
        // family when a previous NAT generation actually left owned state;
        // this still makes NAT -> routing reloads remove the old generation.
        for command in ["iptables", "ip6tables"] {
            if v2_nat_family_has_owned_state(command)? {
                cleanup_v2_nat_family(command)?;
            }
        }
        if !prefixes.is_empty() {
            info!(prefixes = prefixes.len(), "V2 subnet uses pure routing");
        }
        return Ok(());
    }

    for (command, family_v4) in [("iptables", true), ("ip6tables", false)] {
        let family = prefixes
            .iter()
            .filter(|prefix| prefix.addr().is_ipv4() == family_v4)
            .copied()
            .collect::<Vec<_>>();
        if family.is_empty() {
            cleanup_v2_nat_family(command)?;
        } else {
            install_v2_nat_family(command, tun_name, &family)?;
        }
    }
    info!(
        interface = tun_name,
        prefixes = prefixes.len(),
        "enabled V2 subnet NAT"
    );
    Ok(())
}

/// Remove every V2-owned NAT generation. The daemon calls this only when its
/// supervisor exits; ordinary peer loss and data-plane generation rebuilds
/// intentionally leave the active kernel/conntrack topology in place.
pub(crate) fn cleanup_v2_nat_all() -> Result<()> {
    cleanup_v2_nat_family("iptables")?;
    cleanup_v2_nat_family("ip6tables")
}

fn set_forwarding(key: &str) -> Result<()> {
    let output = Command::new("sysctl")
        .args(["-q", "-w", &format!("{key}=1")])
        .output()
        .context("enabling V2 kernel forwarding")?;
    ensure!(
        output.status.success(),
        "enabling V2 kernel forwarding failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn install_v2_nat_family(command: &str, tun_name: &str, prefixes: &[IpNet]) -> Result<()> {
    ensure!(!prefixes.is_empty(), "V2 NAT generation has no prefixes");
    let active_slot = V2_NAT_INGRESS_CHAINS
        .iter()
        .position(|chain| firewall_rule_exists(command, "mangle", "PREROUTING", chain));
    let next_slot = active_slot.map_or(0, |slot| 1 - slot);
    let ingress = V2_NAT_INGRESS_CHAINS[next_slot];
    let egress = V2_NAT_EGRESS_CHAINS[next_slot];

    // Recover a partially installed inactive slot before constructing the new
    // generation. The active slot remains untouched until both replacement
    // chains are fully populated.
    cleanup_v2_nat_chain(command, "mangle", "PREROUTING", ingress)?;
    cleanup_v2_nat_chain(command, "nat", "POSTROUTING", egress)?;
    run_firewall(command, &["-t", "mangle", "-N", ingress])?;
    run_firewall(
        command,
        &[
            "-t",
            "mangle",
            "-A",
            ingress,
            "-i",
            tun_name,
            "-j",
            "CONNMARK",
            "--set-xmark",
            V2_NAT_CONNMARK,
        ],
    )?;
    run_firewall(command, &["-t", "nat", "-N", egress])?;
    for prefix in prefixes {
        run_firewall(
            command,
            &[
                "-t",
                "nat",
                "-A",
                egress,
                "-m",
                "connmark",
                "--mark",
                V2_NAT_CONNMARK,
                "-d",
                &prefix.to_string(),
                "-j",
                "MASQUERADE",
            ],
        )?;
    }

    // Install the egress decision before admitting newly marked ingress
    // connections. During the overlap both generations are valid and the
    // CONNMARK operation is idempotent, so there is no rule-free interval.
    run_firewall(
        command,
        &["-t", "nat", "-I", "POSTROUTING", "1", "-j", egress],
    )?;
    run_firewall(
        command,
        &["-t", "mangle", "-I", "PREROUTING", "1", "-j", ingress],
    )?;

    for slot in 0..V2_NAT_INGRESS_CHAINS.len() {
        if slot != next_slot {
            cleanup_v2_nat_chain(command, "mangle", "PREROUTING", V2_NAT_INGRESS_CHAINS[slot])?;
            cleanup_v2_nat_chain(command, "nat", "POSTROUTING", V2_NAT_EGRESS_CHAINS[slot])?;
        }
    }
    cleanup_v2_nat_chain(command, "mangle", "PREROUTING", LEGACY_V2_NAT_INGRESS_CHAIN)?;
    cleanup_v2_nat_chain(command, "nat", "POSTROUTING", LEGACY_V2_NAT_EGRESS_CHAIN)
}

fn firewall_rule_exists(command: &str, table: &str, hook: &str, chain: &str) -> bool {
    Command::new(command)
        .args(["-t", table, "-C", hook, "-j", chain])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn cleanup_v2_nat_chain(command: &str, table: &str, hook: &str, chain: &str) -> Result<()> {
    loop {
        let output = Command::new(command)
            .args(["-t", table, "-D", hook, "-j", chain])
            .output()
            .with_context(|| format!("removing V2 NAT jump with {command}"))?;
        if !output.status.success() {
            break;
        }
    }
    for action in ["-F", "-X"] {
        Command::new(command)
            .args(["-t", table, action, chain])
            .output()
            .with_context(|| format!("cleaning V2 NAT chain with {command}"))?;
    }
    Ok(())
}

fn cleanup_v2_nat_family(command: &str) -> Result<()> {
    if !firewall_command_available(command)? {
        return Ok(());
    }
    for chain in V2_NAT_INGRESS_CHAINS
        .iter()
        .copied()
        .chain(std::iter::once(LEGACY_V2_NAT_INGRESS_CHAIN))
    {
        cleanup_v2_nat_chain(command, "mangle", "PREROUTING", chain)?;
    }
    for chain in V2_NAT_EGRESS_CHAINS
        .iter()
        .copied()
        .chain(std::iter::once(LEGACY_V2_NAT_EGRESS_CHAIN))
    {
        cleanup_v2_nat_chain(command, "nat", "POSTROUTING", chain)?;
    }
    Ok(())
}

fn firewall_command_available(command: &str) -> Result<bool> {
    match Command::new(command).arg("--version").output() {
        Ok(output) => {
            ensure!(
                output.status.success(),
                "checking {command} availability failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("checking {command} availability")),
    }
}

fn v2_nat_family_has_owned_state(command: &str) -> Result<bool> {
    if !firewall_command_available(command)? {
        return Ok(false);
    }
    for table in ["mangle", "nat"] {
        let output = Command::new(command)
            .args(["-t", table, "-S"])
            .output()
            .with_context(|| format!("inspecting {command} V2 NAT state"))?;
        ensure!(
            output.status.success(),
            "inspecting {command} V2 NAT state failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let rules = String::from_utf8_lossy(&output.stdout);
        if V2_NAT_INGRESS_CHAINS
            .iter()
            .chain(V2_NAT_EGRESS_CHAINS.iter())
            .copied()
            .chain([LEGACY_V2_NAT_INGRESS_CHAIN, LEGACY_V2_NAT_EGRESS_CHAIN])
            .any(|chain| rules.contains(chain))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn run_firewall(command: &str, arguments: &[&str]) -> Result<()> {
    let output = Command::new(command)
        .args(arguments)
        .output()
        .with_context(|| format!("executing {command} for V2 subnet NAT"))?;
    ensure!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn run_ip<const N: usize>(arguments: [&str; N]) -> Result<()> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .context("executing iproute2 for V2 TUN")?;
    if !output.status.success() {
        bail!(
            "iproute2 failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn configure_tun_egress_aqm(tun_name: &str) -> Result<()> {
    let packet_limit = TUN_FQ_CODEL_PACKET_LIMIT.to_string();
    let memory_limit = TUN_FQ_CODEL_MEMORY_BYTES.to_string();
    let output = Command::new("tc")
        .args([
            "qdisc",
            "replace",
            "dev",
            tun_name,
            "root",
            "fq_codel",
            "limit",
            &packet_limit,
            "memory_limit",
            &memory_limit,
            "ecn",
        ])
        .output()
        .context("executing tc for V2 TUN egress AQM")?;
    ensure!(
        output.status.success(),
        "tc fq_codel setup failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    info!(
        interface = tun_name,
        packet_limit = TUN_FQ_CODEL_PACKET_LIMIT,
        memory_limit_bytes = TUN_FQ_CODEL_MEMORY_BYTES,
        "configured V2 TUN fq_codel backpressure boundary"
    );
    Ok(())
}

fn run_ip_vec(arguments: &[String]) -> Result<()> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .context("executing iproute2 for V2 policy route")?;
    ensure!(
        output.status.success(),
        "iproute2 failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn host_prefix_v2(address: IpAddr) -> String {
    format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
}

fn remove_ip_rule(
    family: &str,
    priority: u32,
    table: u32,
    destination: Option<&str>,
) -> Result<()> {
    let priority = priority.to_string();
    let table = table.to_string();
    // Repeatedly delete to recover duplicates left by a killed older build.
    // The first non-zero status means the owned key no longer exists.
    for _ in 0..32 {
        let mut arguments = vec![family, "rule", "del", "priority", &priority];
        if let Some(destination) = destination {
            arguments.extend(["to", destination]);
        }
        arguments.extend(["lookup", if table == "254" { "main" } else { &table }]);
        let output = Command::new("ip")
            .args(arguments)
            .output()
            .context("removing stale V2 policy-routing rule")?;
        if !output.status.success() {
            break;
        }
    }
    Ok(())
}

fn run_ip_allow_failure<const N: usize>(arguments: [&str; N]) -> Result<()> {
    Command::new("ip")
        .args(arguments)
        .output()
        .context("executing idempotent iproute2 cleanup")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use iroh::SecretKey;

    use super::*;

    #[test]
    fn tun_fq_codel_memory_tracks_the_bounded_userspace_merge_window() {
        assert_eq!(TUN_REGULAR_INPUT_BYTES, 512 * 1024);
        assert_eq!(TUN_FQ_CODEL_MEMORY_BYTES, 1024 * 1024);
        assert_eq!(TUN_FQ_CODEL_MEMORY_BYTES, TUN_REGULAR_INPUT_BYTES * 2);
    }

    #[test]
    fn derived_addresses_are_stable_network_and_endpoint_scoped() {
        let one = SecretKey::from_bytes(&[1; 32]).public();
        let two = SecretKey::from_bytes(&[2; 32]).public();
        let first = derived_overlay_address("network-a", one);
        assert_eq!(first, derived_overlay_address("network-a", one));
        assert_ne!(first, derived_overlay_address("network-a", two));
        assert_ne!(first, derived_overlay_address("network-b", one));
        assert_eq!(first.octets()[0], 0xfd);

        let first_v4 = derived_overlay_ipv4_address("network-a", one);
        assert_eq!(first_v4, derived_overlay_ipv4_address("network-a", one));
        assert_ne!(first_v4, derived_overlay_ipv4_address("network-a", two));
        assert_ne!(first_v4, derived_overlay_ipv4_address("network-b", one));
        assert!(
            ipnet::Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10)
                .unwrap()
                .contains(&first_v4)
        );
    }

    #[test]
    fn product_node_addresses_override_lab_derivation() {
        let config: crate::config::Config =
            toml::from_str(include_str!("../../config/example.toml")).unwrap();
        let runtime = V2RuntimeConfig::from_product_config(&config).unwrap();
        let endpoint = SecretKey::from_bytes(&[3; 32]).public();
        let (ipv4, ipv6) = local_overlay_addresses(&runtime, endpoint);
        assert_eq!(ipv4, "21.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ipv6, "21::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn missing_optional_firewall_tools_mean_no_owned_nat_state() {
        let missing = "ironet-v2-test-firewall-command-that-does-not-exist";
        assert!(!firewall_command_available(missing).unwrap());
        assert!(!v2_nat_family_has_owned_state(missing).unwrap());
        cleanup_v2_nat_family(missing).unwrap();
    }
}
