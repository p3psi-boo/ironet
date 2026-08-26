//! Overlay address-pool validation, collision detection, and allocation.

use super::*;

pub(super) fn validate_address_pool(pool: Ipv4Net) -> Result<()> {
    ensure!(
        pool.prefix_len() <= 24,
        "address pool must provide at least 256 addresses"
    );
    ensure!(pool.prefix_len() >= 8, "address pool is too broad");
    Ok(())
}

pub(super) fn validate_ipv6_address_pool(pool: Ipv6Net) -> Result<()> {
    ensure!(
        pool.prefix_len() <= 120,
        "IPv6 address pool must provide at least 256 addresses"
    );
    ensure!(
        pool.prefix_len() >= 48,
        "IPv6 address pool is too broad; use a /48 to /120 ULA prefix"
    );
    let ula: Ipv6Net = "fc00::/7".parse().expect("valid ULA prefix");
    ensure!(
        ula.contains(&pool.network()),
        "IPv6 address pool must use the ULA range fc00::/7"
    );
    Ok(())
}

pub(super) fn select_address_pool(seed: EndpointId) -> Result<Ipv4Net> {
    let routes = local_ipv4_routes();
    let start = usize::from(blake3::hash(seed.as_bytes()).as_bytes()[0]);
    // Prefer a collision-free /16 from CGNAT space, then RFC1918 space. Searching small
    // pools avoids rejecting all of 100.64/10 merely because another VPN uses one slice.
    let candidates = (0..64)
        .map(|offset| 64 + ((start + offset) % 64) as u8)
        .map(|second| Ipv4Net::new(Ipv4Addr::new(100, second, 0, 0), 16).expect("valid pool"))
        .chain((0..16).map(|offset| {
            Ipv4Net::new(
                Ipv4Addr::new(172, 16 + ((start + offset) % 16) as u8, 0, 0),
                16,
            )
            .expect("valid pool")
        }))
        .chain((0..256).map(|offset| {
            Ipv4Net::new(Ipv4Addr::new(10, ((start + offset) % 256) as u8, 0, 0), 16)
                .expect("valid pool")
        }));
    candidates
        .into_iter()
        .find(|candidate| {
            !routes
                .iter()
                .any(|route| ipv4_nets_overlap(*candidate, *route))
        })
        .context("no collision-free automatic IPv4 address pool is available; pass --address-pool")
}

pub(super) fn select_ipv6_address_pool(seed: EndpointId) -> Result<Ipv6Net> {
    let routes = local_ipv6_routes();
    (0_u16..=u16::MAX)
        .map(|subnet| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"ironet-auto-ipv6-pool-v2\0");
            hasher.update(seed.as_bytes());
            hasher.update(&subnet.to_be_bytes());
            let hash = hasher.finalize();
            let bytes = hash.as_bytes();
            let address = Ipv6Addr::from([
                0xfd, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], 0, 0,
                0, 0, 0, 0, 0, 0,
            ]);
            Ipv6Net::new(address, 64).expect("valid automatic IPv6 pool")
        })
        .find(|candidate| {
            !routes
                .iter()
                .any(|route| ipv6_nets_overlap(*candidate, *route))
        })
        .context(
            "no collision-free automatic IPv6 address pool is available; pass --ipv6-address-pool",
        )
}

pub(super) fn ensure_local_pool_available(pool: Ipv4Net) -> Result<()> {
    if let Some(route) = local_ipv4_routes()
        .into_iter()
        .find(|route| ipv4_nets_overlap(pool, *route))
    {
        bail!("address pool {pool} overlaps local route {route}");
    }
    Ok(())
}

pub(super) fn ensure_local_ipv6_pool_available(pool: Ipv6Net) -> Result<()> {
    if let Some(route) = local_ipv6_routes()
        .into_iter()
        .find(|route| ipv6_nets_overlap(pool, *route))
    {
        bail!("IPv6 address pool {pool} overlaps local route {route}");
    }
    Ok(())
}

fn local_ipv4_routes() -> Vec<Ipv4Net> {
    let Ok(output) = std::process::Command::new("ip")
        .args(["-4", "route", "show", "table", "all"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|value| *value != "default")
        .filter_map(|value| {
            value.parse::<Ipv4Net>().ok().or_else(|| {
                value
                    .parse::<Ipv4Addr>()
                    .ok()
                    .map(|address| Ipv4Net::new(address, 32).expect("valid host route"))
            })
        })
        .collect()
}

fn local_ipv6_routes() -> Vec<Ipv6Net> {
    let Ok(output) = std::process::Command::new("ip")
        .args(["-6", "route", "show", "table", "all"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let ula: Ipv6Net = "fc00::/7".parse().expect("valid ULA prefix");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|value| *value != "default")
        .filter_map(|value| {
            value.parse::<Ipv6Net>().ok().or_else(|| {
                value
                    .parse::<Ipv6Addr>()
                    .ok()
                    .map(|address| Ipv6Net::new(address, 128).expect("valid IPv6 host route"))
            })
        })
        // Ignore default and split-default routes installed by general VPNs.
        // Only ULA-specific routes can conflict with an Overlay ULA pool.
        .filter(|route| route.prefix_len() >= ula.prefix_len() && ula.contains(&route.network()))
        .collect()
}

fn ipv4_nets_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

fn ipv6_nets_overlap(left: Ipv6Net, right: Ipv6Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

pub(super) fn allocate_address(pool: Ipv4Net, endpoint: EndpointId) -> IpNet {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-auto-address-v2\0");
    hasher.update(pool.to_string().as_bytes());
    hasher.update(endpoint.as_bytes());
    let hash = hasher.finalize();
    let raw = u32::from_be_bytes(hash.as_bytes()[..4].try_into().expect("four bytes"));
    let host_bits = 32 - pool.prefix_len();
    let host_mask = if host_bits == 32 {
        u32::MAX
    } else {
        (1u32 << host_bits) - 1
    };
    let usable = host_mask.saturating_sub(1).max(1);
    let host = 1 + raw % usable;
    let network = u32::from(pool.network());
    IpNet::new(IpAddr::V4(Ipv4Addr::from(network | host)), 32).expect("valid IPv4 host")
}

pub(super) fn allocate_ipv6_address(pool: Ipv6Net, endpoint: EndpointId) -> IpNet {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-auto-ipv6-address-v2\0");
    hasher.update(pool.to_string().as_bytes());
    hasher.update(endpoint.as_bytes());
    let hash = hasher.finalize();
    let raw = u128::from_be_bytes(hash.as_bytes()[..16].try_into().expect("sixteen bytes"));
    let host_bits = 128 - pool.prefix_len();
    let host_mask = (1_u128 << host_bits) - 1;
    let usable = host_mask.saturating_sub(1).max(1);
    let host = 1 + raw % usable;
    let network = u128::from(pool.network());
    IpNet::new(IpAddr::V6(Ipv6Addr::from(network | host)), 128).expect("valid IPv6 host")
}
