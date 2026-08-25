use std::{net::IpAddr, sync::Arc, time::Duration};

use ipnet::IpNet;

use super::{FlowRouteLeaseV2, RouteQualityV2, bytes_for_duration, transfer_time};
use crate::protocol::v2::routing::{
    AdjacencyIdV2, DataplaneSnapshotV2, PrefixRouteV2, ResolvedRouteV2, RouteLabelV2,
};

const DESTINATION: &str = "11.6.1.48";
const DIRECT_CAPACITY_BPS: u64 = 1_000_000;
const TRANSIT_CAPACITY_BPS: u64 = 100_000_000;
const DIRECT_LATENCY: Duration = Duration::from_millis(1);
const TRANSIT_LATENCY: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy)]
struct TestTopology {
    direct: ResolvedRouteV2,
    transit: ResolvedRouteV2,
}

impl TestTopology {
    fn new() -> Self {
        Self {
            direct: route(13, 1),
            transit: route(12, 2),
        }
    }

    fn snapshot(self, generation: u64, include_transit: bool) -> Arc<DataplaneSnapshotV2> {
        let prefix: IpNet = "11.6.1.0/24".parse().unwrap();
        let mut routes = vec![PrefixRouteV2 {
            prefix,
            route: self.direct,
            startup_latency: DIRECT_LATENCY,
        }];
        if include_transit {
            routes.push(PrefixRouteV2 {
                prefix,
                route: self.transit,
                startup_latency: TRANSIT_LATENCY,
            });
        }
        Arc::new(
            DataplaneSnapshotV2::compile(
                generation,
                [1; 32],
                routes,
                Vec::new(),
                Vec::new(),
                false,
            )
            .unwrap(),
        )
    }

    fn lease(self) -> FlowRouteLeaseV2 {
        FlowRouteLeaseV2::resolve(self.snapshot(1, true), destination()).unwrap()
    }
}

#[derive(Debug)]
struct PathState {
    route: ResolvedRouteV2,
    latency: Duration,
    capacity_bps: u64,
    queued_bytes: u64,
    last_completion: Duration,
}

impl PathState {
    fn new(route: ResolvedRouteV2, latency: Duration, capacity_bps: u64) -> Self {
        Self {
            route,
            latency,
            capacity_bps,
            queued_bytes: 0,
            last_completion: Duration::ZERO,
        }
    }

    fn advance(&mut self, elapsed: Duration) {
        self.queued_bytes = self
            .queued_bytes
            .saturating_sub(bytes_for_duration(self.capacity_bps / 8, elapsed));
    }

    fn enqueue(&mut self, now: Duration, bytes: usize) {
        self.queued_bytes = self.queued_bytes.saturating_add(bytes as u64);
        self.last_completion = now
            .saturating_add(self.latency)
            .saturating_add(transfer_time(self.queued_bytes, self.capacity_bps));
    }
}

#[derive(Debug)]
struct EvaluationReport {
    completion: Duration,
    direct_only_completion: Duration,
    switches: u64,
    direct_bytes: u64,
    transit_bytes: u64,
}

fn simulate_bulk(total_bytes: u64) -> EvaluationReport {
    const STEP: Duration = Duration::from_millis(10);
    const PACKET_BYTES: usize = 16 * 1024;

    let topology = TestTopology::new();
    let mut lease = topology.lease();
    let mut direct = PathState::new(topology.direct, DIRECT_LATENCY, DIRECT_CAPACITY_BPS);
    let mut transit = PathState::new(topology.transit, TRANSIT_LATENCY, TRANSIT_CAPACITY_BPS);
    let mut now = Duration::ZERO;
    let mut submitted = 0_u64;
    let mut switches = 0_u64;
    let mut previous = lease.route();
    let mut direct_bytes = 0_u64;
    let mut transit_bytes = 0_u64;

    while submitted < total_bytes {
        if !now.is_zero() {
            direct.advance(STEP);
            transit.advance(STEP);
        }
        let packet_bytes = (total_bytes - submitted).min(PACKET_BYTES as u64) as usize;
        let direct_queue = direct.queued_bytes;
        let transit_queue = transit.queued_bytes;
        let selected = lease.select(now, packet_bytes, |route| {
            if route == topology.direct {
                RouteQualityV2 {
                    capacity_bits_per_second: DIRECT_CAPACITY_BPS,
                    queued_bytes: direct_queue,
                }
            } else {
                RouteQualityV2 {
                    capacity_bits_per_second: TRANSIT_CAPACITY_BPS,
                    queued_bytes: transit_queue,
                }
            }
        });
        if selected != previous {
            switches += 1;
            previous = selected;
        }
        if selected == direct.route {
            direct.enqueue(now, packet_bytes);
            direct_bytes += packet_bytes as u64;
        } else {
            transit.enqueue(now, packet_bytes);
            transit_bytes += packet_bytes as u64;
        }
        submitted += packet_bytes as u64;
        now = now.saturating_add(STEP);
    }

    EvaluationReport {
        completion: direct.last_completion.max(transit.last_completion),
        direct_only_completion: DIRECT_LATENCY
            .saturating_add(transfer_time(total_bytes, DIRECT_CAPACITY_BPS)),
        switches,
        direct_bytes,
        transit_bytes,
    }
}

#[test]
fn short_flows_keep_the_low_latency_direct_route() {
    let topology = TestTopology::new();
    for bytes in [256, 512, 1_024, 2_048, 4_096] {
        let mut lease = topology.lease();
        let selected = lease.select(Duration::ZERO, bytes, |route| RouteQualityV2 {
            capacity_bits_per_second: if route == topology.direct {
                DIRECT_CAPACITY_BPS
            } else {
                TRANSIT_CAPACITY_BPS
            },
            queued_bytes: 0,
        });
        assert_eq!(
            selected, topology.direct,
            "{bytes}-byte short flow moved to transit"
        );
    }
}

#[test]
fn bulk_completion_beats_direct_only_without_oscillation() {
    let report = simulate_bulk(16 * 1024 * 1024);
    let improvement =
        1.0 - report.completion.as_secs_f64() / report.direct_only_completion.as_secs_f64();
    let improvement_percent = improvement * 100.0;
    eprintln!("A/B/C bulk evaluation: {report:?}, improvement={improvement_percent:.1}%");

    assert!(
        improvement >= 0.20,
        "Bulk completion improvement was only {improvement_percent:.1}%"
    );
    assert_eq!(report.switches, 1, "Bulk route oscillated");
    assert!(report.direct_bytes > 0, "Bulk skipped direct-route startup");
    assert!(
        report.transit_bytes > report.direct_bytes,
        "Bulk did not move most bytes to transit"
    );
}

#[test]
fn sub_lease_congestion_burst_does_not_trigger_migration() {
    let topology = TestTopology::new();
    let mut lease = topology.lease();
    let quality = |route| RouteQualityV2 {
        capacity_bits_per_second: if route == topology.direct {
            DIRECT_CAPACITY_BPS
        } else {
            TRANSIT_CAPACITY_BPS
        },
        queued_bytes: if route == topology.direct {
            4 * 1024 * 1024
        } else {
            0
        },
    };

    assert_eq!(
        lease.select(Duration::ZERO, 64, |_| RouteQualityV2 {
            capacity_bits_per_second: DIRECT_CAPACITY_BPS,
            queued_bytes: 0,
        }),
        topology.direct
    );
    for millis in [10, 20, 40, 80] {
        assert_eq!(
            lease.select(Duration::from_millis(millis), 128 * 1024, quality),
            topology.direct
        );
    }
    assert_eq!(
        lease.select(Duration::from_millis(1_100), 64, |route| RouteQualityV2 {
            capacity_bits_per_second: if route == topology.direct {
                DIRECT_CAPACITY_BPS
            } else {
                TRANSIT_CAPACITY_BPS
            },
            queued_bytes: 0,
        }),
        topology.direct
    );
}

#[test]
fn alternating_capacity_noise_does_not_cause_route_flapping() {
    let topology = TestTopology::new();
    let mut lease = topology.lease();
    let mut previous = lease.route();
    let mut switches = 0_u64;

    for tick in 0..=6_000_u64 {
        let now = Duration::from_millis(tick * 100);
        let direct_is_faster = (tick / 10).is_multiple_of(2);
        let selected = lease.select(now, 1024 * 1024, |route| RouteQualityV2 {
            capacity_bits_per_second: match (route == topology.direct, direct_is_faster) {
                (true, true) | (false, false) => 52_000_000,
                _ => 48_000_000,
            },
            queued_bytes: 0,
        });
        if selected != previous {
            switches += 1;
            previous = selected;
        }
    }

    assert!(
        switches <= 2,
        "measurement noise caused {switches} switches in ten minutes"
    );
}

#[test]
fn failed_transit_candidate_is_removed_immediately_on_snapshot_refresh() {
    let topology = TestTopology::new();
    let mut lease = topology.lease();
    for tick in 0..=30 {
        lease.select(Duration::from_millis(tick * 100), 128 * 1024, |route| {
            RouteQualityV2 {
                capacity_bits_per_second: if route == topology.direct {
                    DIRECT_CAPACITY_BPS
                } else {
                    TRANSIT_CAPACITY_BPS
                },
                queued_bytes: 0,
            }
        });
    }
    assert_eq!(lease.route(), topology.transit);

    assert!(lease.refresh(topology.snapshot(2, false)).unwrap());
    assert_eq!(lease.route(), topology.direct);
}

fn destination() -> IpAddr {
    DESTINATION.parse().unwrap()
}

fn route(adjacency: u32, label: u32) -> ResolvedRouteV2 {
    ResolvedRouteV2 {
        adjacency: AdjacencyIdV2::new(adjacency).unwrap(),
        route_label: RouteLabelV2::new(label).unwrap(),
        route_epoch: 7,
        maximum_datagram_size: 1_382,
    }
}
