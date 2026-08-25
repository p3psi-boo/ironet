use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Result, ensure};
use rustc_hash::FxHashMap as HashMap;

use crate::protocol::v2::{
    route_feedback::RouteDeliveryFeedbackV2,
    routing::{DataplaneSnapshotV2, MAX_ROUTE_LABELS, ResolvedRouteV2},
};

const ROUTE_LEASE: Duration = Duration::from_secs(1);
const ROUTE_IDLE_RESET: Duration = Duration::from_secs(2);
const ROUTE_SWITCH_PENALTY: Duration = Duration::from_millis(25);
const ROUTE_SWITCH_GAIN_DIVISOR: u32 = 20;
const ROUTE_SWITCH_CONFIRMATIONS: u8 = 2;
const PRESSURE_DRAIN_BYTES_PER_SECOND: u64 = 256 * 1024;
const PACKET_ALLOWANCE_BYTES: usize = 256;
const MAX_PRESSURE_BYTES: u64 = 64 * 1024 * 1024;
const UNKNOWN_ROUTE_CAPACITY_BPS: u64 = 10_000_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RouteQualityV2 {
    pub capacity_bits_per_second: u64,
    pub queued_bytes: u64,
}

#[derive(Debug, Clone)]
pub(super) struct FlowRouteLeaseV2 {
    snapshot: Arc<DataplaneSnapshotV2>,
    destination: IpAddr,
    candidates: Vec<(ResolvedRouteV2, Duration)>,
    selected: usize,
    pending_selection: Option<usize>,
    pending_confirmations: u8,
    lease_until: Duration,
    pressure_bytes: u64,
    updated_at: Option<Duration>,
}

impl FlowRouteLeaseV2 {
    pub fn resolve(snapshot: Arc<DataplaneSnapshotV2>, destination: IpAddr) -> Result<Self> {
        let candidates = snapshot
            .lookup_destination_candidates(destination)
            .map_err(|reason| anyhow::anyhow!("V2 flow route lookup failed: {reason:?}"))?;
        ensure!(!candidates.is_empty(), "V2 flow route has no candidates");
        Ok(Self {
            snapshot,
            destination,
            candidates,
            selected: 0,
            pending_selection: None,
            pending_confirmations: 0,
            lease_until: Duration::ZERO,
            pressure_bytes: 0,
            updated_at: None,
        })
    }

    pub fn route(&self) -> ResolvedRouteV2 {
        self.candidates[self.selected].0
    }

    #[cfg(test)]
    fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub fn select(
        &mut self,
        now: Duration,
        packet_len: usize,
        quality: impl Fn(ResolvedRouteV2) -> RouteQualityV2,
    ) -> ResolvedRouteV2 {
        let elapsed = self
            .updated_at
            .map_or(Duration::ZERO, |updated| now.saturating_sub(updated));
        if elapsed >= ROUTE_IDLE_RESET {
            self.pressure_bytes = 0;
            self.lease_until = Duration::ZERO;
        } else {
            self.pressure_bytes = self
                .pressure_bytes
                .saturating_sub(bytes_for_duration(PRESSURE_DRAIN_BYTES_PER_SECOND, elapsed));
        }
        self.pressure_bytes = self
            .pressure_bytes
            .saturating_add(packet_len.saturating_sub(PACKET_ALLOWANCE_BYTES) as u64)
            .min(MAX_PRESSURE_BYTES);
        self.updated_at = Some(now);

        if now < self.lease_until {
            return self.route();
        }

        let previous = self.route();
        let score = |route: ResolvedRouteV2, startup_latency: Duration| {
            let quality = quality(route);
            let capacity = if quality.capacity_bits_per_second == 0 {
                UNKNOWN_ROUTE_CAPACITY_BPS
            } else {
                quality.capacity_bits_per_second
            };
            let switch_penalty = if route == previous {
                Duration::ZERO
            } else {
                ROUTE_SWITCH_PENALTY
            };
            startup_latency
                .saturating_add(transfer_time(
                    self.pressure_bytes.saturating_add(quality.queued_bytes),
                    capacity,
                ))
                .saturating_add(switch_penalty)
        };
        let best = self
            .candidates
            .iter()
            .enumerate()
            .min_by_key(|(_, (route, startup_latency))| score(*route, *startup_latency))
            .map(|(index, _)| index)
            .unwrap_or_default();
        let current_score = score(
            self.candidates[self.selected].0,
            self.candidates[self.selected].1,
        );
        let best_score = score(self.candidates[best].0, self.candidates[best].1);
        let minimum_gain = current_score / ROUTE_SWITCH_GAIN_DIVISOR;
        let has_material_gain =
            best != self.selected && current_score.saturating_sub(best_score) > minimum_gain;

        if has_material_gain {
            if self.pending_selection == Some(best) {
                self.pending_confirmations = self.pending_confirmations.saturating_add(1);
            } else {
                self.pending_selection = Some(best);
                self.pending_confirmations = 1;
            }
            if self.pending_confirmations >= ROUTE_SWITCH_CONFIRMATIONS {
                self.selected = best;
                self.clear_pending_selection();
            }
        } else {
            self.clear_pending_selection();
        }
        self.lease_until = now.saturating_add(ROUTE_LEASE);
        self.route()
    }

    pub fn snapshot_generation(&self) -> u64 {
        self.snapshot.generation()
    }

    pub fn refresh(&mut self, snapshot: Arc<DataplaneSnapshotV2>) -> Result<bool> {
        if snapshot.generation() == self.snapshot.generation() {
            return Ok(false);
        }
        self.candidates = snapshot
            .lookup_destination_candidates(self.destination)
            .map_err(|reason| anyhow::anyhow!("V2 flow route refresh failed: {reason:?}"))?;
        ensure!(
            !self.candidates.is_empty(),
            "V2 flow route has no candidates"
        );
        self.selected = 0;
        self.clear_pending_selection();
        self.lease_until = Duration::ZERO;
        self.snapshot = snapshot;
        Ok(true)
    }

    fn clear_pending_selection(&mut self) {
        self.pending_selection = None;
        self.pending_confirmations = 0;
    }
}

#[cfg(test)]
mod evaluation;

#[derive(Debug, Clone, Copy)]
struct RouteCapacitySampleV2 {
    sequence: u64,
    capacity_bps: u64,
}

#[derive(Debug, Default)]
pub(super) struct RouteQualityTableV2 {
    samples: Mutex<HashMap<(u32, u32), RouteCapacitySampleV2>>,
}

impl RouteQualityTableV2 {
    pub fn observe(&self, feedback: RouteDeliveryFeedbackV2) {
        let mut samples = self
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if samples.len() >= MAX_ROUTE_LABELS
            && !samples.contains_key(&(feedback.route_epoch, feedback.route_label.0))
        {
            samples.clear();
        }
        let capacity_bps = feedback.delivery_rate_bps();
        samples
            .entry((feedback.route_epoch, feedback.route_label.0))
            .and_modify(|sample| {
                if feedback.sequence > sample.sequence {
                    sample.sequence = feedback.sequence;
                    sample.capacity_bps = sample.capacity_bps.max(capacity_bps);
                }
            })
            .or_insert(RouteCapacitySampleV2 {
                sequence: feedback.sequence,
                capacity_bps,
            });
    }

    pub fn effective_capacity_bps(&self, route: ResolvedRouteV2, first_hop_bps: u64) -> u64 {
        let end_to_end_bps = self
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(route.route_epoch, route.route_label.0))
            .map_or(0, |sample| sample.capacity_bps);
        match (first_hop_bps, end_to_end_bps) {
            (0, end_to_end) => end_to_end,
            (first_hop, 0) => first_hop,
            (first_hop, end_to_end) => first_hop.min(end_to_end),
        }
    }
}

fn bytes_for_duration(bytes_per_second: u64, duration: Duration) -> u64 {
    (u128::from(bytes_per_second).saturating_mul(duration.as_nanos()) / 1_000_000_000)
        .min(u128::from(u64::MAX)) as u64
}

fn transfer_time(bytes: u64, capacity_bits_per_second: u64) -> Duration {
    if bytes == 0 {
        return Duration::ZERO;
    }
    let nanos = u128::from(bytes)
        .saturating_mul(8)
        .saturating_mul(1_000_000_000)
        .div_ceil(u128::from(capacity_bits_per_second.max(1)));
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    use super::*;
    use crate::protocol::v2::routing::{AdjacencyIdV2, PrefixRouteV2, RouteLabelV2};

    fn route(adjacency: u32, label: u32) -> ResolvedRouteV2 {
        ResolvedRouteV2 {
            adjacency: AdjacencyIdV2::new(adjacency).unwrap(),
            route_label: RouteLabelV2::new(label).unwrap(),
            route_epoch: 7,
            maximum_datagram_size: 1_382,
        }
    }

    #[test]
    fn sustained_flow_moves_from_low_latency_direct_to_high_capacity_transit() {
        let prefix: IpNet = "11.6.1.0/24".parse().unwrap();
        let direct = route(13, 1);
        let transit = route(12, 2);
        let snapshot = Arc::new(
            DataplaneSnapshotV2::compile(
                1,
                [1; 32],
                vec![
                    PrefixRouteV2 {
                        prefix,
                        route: direct,
                        startup_latency: Duration::from_millis(1),
                    },
                    PrefixRouteV2 {
                        prefix,
                        route: transit,
                        startup_latency: Duration::from_millis(50),
                    },
                ],
                Vec::new(),
                Vec::new(),
                false,
            )
            .unwrap(),
        );
        let mut lease = FlowRouteLeaseV2::resolve(snapshot, "11.6.1.48".parse().unwrap()).unwrap();
        assert_eq!(lease.candidate_count(), 2);

        let quality = |route: ResolvedRouteV2| RouteQualityV2 {
            capacity_bits_per_second: if route == direct {
                1_000_000
            } else {
                100_000_000
            },
            queued_bytes: 0,
        };
        assert_eq!(lease.select(Duration::ZERO, 100, quality), direct);
        for tick in 1..=20 {
            lease.select(Duration::from_millis(tick * 100), 128 * 1024, quality);
        }
        assert_eq!(lease.route(), transit);
    }

    #[test]
    fn destination_feedback_caps_first_hop_capacity_and_rejects_replay() {
        let table = RouteQualityTableV2::default();
        let route = route(12, 2);
        table.observe(RouteDeliveryFeedbackV2 {
            sequence: 4,
            route_epoch: route.route_epoch,
            route_label: route.route_label,
            delivered_payload_bytes: 6_250_000,
            interval_micros: 1_000_000,
        });
        assert_eq!(table.effective_capacity_bps(route, 100_000_000), 50_000_000);

        table.observe(RouteDeliveryFeedbackV2 {
            sequence: 3,
            route_epoch: route.route_epoch,
            route_label: route.route_label,
            delivered_payload_bytes: 1,
            interval_micros: 1_000_000,
        });
        assert_eq!(table.effective_capacity_bps(route, 100_000_000), 50_000_000);
    }
}
