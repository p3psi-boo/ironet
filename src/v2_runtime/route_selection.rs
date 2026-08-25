use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use rustc_hash::FxHashMap as HashMap;
use smallvec::SmallVec;

use crate::protocol::v2::{
    route_feedback::RouteDeliveryFeedbackV2,
    routing::{DataplaneSnapshotV2, MAX_ROUTE_LABELS, ResolvedRouteV2},
};

const ROUTE_CAPACITY_WINDOW: Duration = Duration::from_secs(30);
const MAX_ROUTE_CAPACITY_SAMPLES: usize = 64;

#[derive(Debug, Clone, Copy)]
struct RouteSelectionPolicyV2 {
    lease: Duration,
    idle_reset: Duration,
    switch_penalty: Duration,
    switch_gain_divisor: u32,
    switch_confirmations: u8,
    pressure_drain_bytes_per_second: u64,
    packet_allowance_bytes: usize,
    maximum_pressure_bytes: u64,
    unknown_capacity_bps: u64,
}

impl Default for RouteSelectionPolicyV2 {
    fn default() -> Self {
        Self {
            lease: Duration::from_secs(1),
            idle_reset: Duration::from_secs(2),
            switch_penalty: Duration::from_millis(25),
            switch_gain_divisor: 20,
            switch_confirmations: 2,
            pressure_drain_bytes_per_second: 256 * 1024,
            packet_allowance_bytes: 256,
            maximum_pressure_bytes: 64 * 1024 * 1024,
            unknown_capacity_bps: 10_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RouteQualityV2 {
    pub capacity_bits_per_second: u64,
    pub queued_bytes: u64,
}

#[derive(Debug, Clone)]
pub(super) struct FlowRouteLeaseV2 {
    policy: RouteSelectionPolicyV2,
    snapshot_generation: u64,
    destination: IpAddr,
    candidates: SmallVec<[(ResolvedRouteV2, Duration); 4]>,
    selected: usize,
    pending_selection: Option<usize>,
    pending_confirmations: u8,
    lease_until: Duration,
    pressure_bytes: u64,
    updated_at: Option<Duration>,
}

impl FlowRouteLeaseV2 {
    pub fn resolve(snapshot: Arc<DataplaneSnapshotV2>, destination: IpAddr) -> Result<Self> {
        let candidates: SmallVec<[(ResolvedRouteV2, Duration); 4]> = snapshot
            .lookup_destination_candidates(destination)
            .map_err(|reason| anyhow::anyhow!("V2 flow route lookup failed: {reason:?}"))?
            .into_iter()
            .collect();
        ensure!(!candidates.is_empty(), "V2 flow route has no candidates");
        Ok(Self {
            policy: RouteSelectionPolicyV2::default(),
            snapshot_generation: snapshot.generation(),
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
        if elapsed >= self.policy.idle_reset {
            self.pressure_bytes = 0;
            self.lease_until = Duration::ZERO;
        } else {
            self.pressure_bytes = self.pressure_bytes.saturating_sub(bytes_for_duration(
                self.policy.pressure_drain_bytes_per_second,
                elapsed,
            ));
        }
        self.pressure_bytes = self
            .pressure_bytes
            .saturating_add(packet_len.saturating_sub(self.policy.packet_allowance_bytes) as u64)
            .min(self.policy.maximum_pressure_bytes);
        self.updated_at = Some(now);

        if now < self.lease_until {
            return self.route();
        }

        let previous = self.route();
        let score = |route: ResolvedRouteV2, startup_latency: Duration| {
            let quality = quality(route);
            let capacity = if quality.capacity_bits_per_second == 0 {
                self.policy.unknown_capacity_bps
            } else {
                quality.capacity_bits_per_second
            };
            let switch_penalty = if route == previous {
                Duration::ZERO
            } else {
                self.policy.switch_penalty
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
        let minimum_gain = current_score / self.policy.switch_gain_divisor;
        let has_material_gain =
            best != self.selected && current_score.saturating_sub(best_score) > minimum_gain;

        if has_material_gain {
            if self.pending_selection == Some(best) {
                self.pending_confirmations = self.pending_confirmations.saturating_add(1);
            } else {
                self.pending_selection = Some(best);
                self.pending_confirmations = 1;
            }
            if self.pending_confirmations >= self.policy.switch_confirmations {
                self.selected = best;
                self.clear_pending_selection();
            }
        } else {
            self.clear_pending_selection();
        }
        self.lease_until = now.saturating_add(self.policy.lease);
        self.route()
    }

    pub fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }

    pub fn refresh(&mut self, snapshot: Arc<DataplaneSnapshotV2>) -> Result<bool> {
        if snapshot.generation() == self.snapshot_generation {
            return Ok(false);
        }
        self.candidates = snapshot
            .lookup_destination_candidates(self.destination)
            .map_err(|reason| anyhow::anyhow!("V2 flow route refresh failed: {reason:?}"))?
            .into_iter()
            .collect();
        ensure!(
            !self.candidates.is_empty(),
            "V2 flow route has no candidates"
        );
        self.selected = 0;
        self.clear_pending_selection();
        self.lease_until = Duration::ZERO;
        self.snapshot_generation = snapshot.generation();
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
    capacity_bps: u64,
    observed_at: Instant,
}

#[derive(Debug, Default)]
struct RouteCapacityWindowV2 {
    last_sequence: u64,
    maxima: VecDeque<RouteCapacitySampleV2>,
}

#[derive(Debug, Default)]
struct RouteQualityStateV2 {
    active_epoch: u32,
    samples: HashMap<u32, RouteCapacityWindowV2>,
}

#[derive(Debug, Default)]
pub(super) struct RouteQualityTableV2 {
    state: Mutex<RouteQualityStateV2>,
}

impl RouteQualityTableV2 {
    pub fn observe(&self, feedback: RouteDeliveryFeedbackV2) {
        self.observe_at(feedback, Instant::now());
    }

    fn observe_at(&self, feedback: RouteDeliveryFeedbackV2, now: Instant) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active_epoch != feedback.route_epoch {
            state.active_epoch = feedback.route_epoch;
            state.samples.clear();
        }
        if state.samples.len() >= MAX_ROUTE_LABELS
            && !state.samples.contains_key(&feedback.route_label.0)
        {
            state.samples.clear();
        }
        let window = state.samples.entry(feedback.route_label.0).or_default();
        if feedback.sequence <= window.last_sequence {
            return;
        }
        window.last_sequence = feedback.sequence;
        prune_capacity_samples(&mut window.maxima, now);
        let capacity_bps = feedback.delivery_rate_bps();
        while window
            .maxima
            .back()
            .is_some_and(|sample| sample.capacity_bps <= capacity_bps)
        {
            window.maxima.pop_back();
        }
        window.maxima.push_back(RouteCapacitySampleV2 {
            capacity_bps,
            observed_at: now,
        });
        while window.maxima.len() > MAX_ROUTE_CAPACITY_SAMPLES {
            window.maxima.pop_front();
        }
    }

    pub fn effective_capacity_bps(&self, route: ResolvedRouteV2, first_hop_bps: u64) -> u64 {
        self.effective_capacity_bps_at(route, first_hop_bps, Instant::now())
    }

    fn effective_capacity_bps_at(
        &self,
        route: ResolvedRouteV2,
        first_hop_bps: u64,
        now: Instant,
    ) -> u64 {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active_epoch != route.route_epoch {
            return first_hop_bps;
        }
        let end_to_end_bps = state
            .samples
            .get_mut(&route.route_label.0)
            .map(|window| {
                prune_capacity_samples(&mut window.maxima, now);
                window
                    .maxima
                    .front()
                    .map_or(0, |sample| sample.capacity_bps)
            })
            .unwrap_or_default();
        match (first_hop_bps, end_to_end_bps) {
            (0, end_to_end) => end_to_end,
            (first_hop, 0) => first_hop,
            (first_hop, end_to_end) => first_hop.min(end_to_end),
        }
    }
}

fn prune_capacity_samples(samples: &mut VecDeque<RouteCapacitySampleV2>, now: Instant) {
    while samples.front().is_some_and(|sample| {
        now.saturating_duration_since(sample.observed_at) > ROUTE_CAPACITY_WINDOW
    }) {
        samples.pop_front();
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
        let started = Instant::now();
        table.observe_at(
            RouteDeliveryFeedbackV2 {
                sequence: 4,
                route_epoch: route.route_epoch,
                route_label: route.route_label,
                delivered_payload_bytes: 6_250_000,
                interval_micros: 1_000_000,
            },
            started,
        );
        assert_eq!(
            table.effective_capacity_bps_at(route, 100_000_000, started),
            50_000_000
        );

        table.observe_at(
            RouteDeliveryFeedbackV2 {
                sequence: 3,
                route_epoch: route.route_epoch,
                route_label: route.route_label,
                delivered_payload_bytes: 1,
                interval_micros: 1_000_000,
            },
            started + Duration::from_secs(1),
        );
        assert_eq!(
            table.effective_capacity_bps_at(route, 100_000_000, started),
            50_000_000
        );

        table.observe_at(
            RouteDeliveryFeedbackV2 {
                sequence: 5,
                route_epoch: route.route_epoch,
                route_label: route.route_label,
                delivered_payload_bytes: 1_250_000,
                interval_micros: 1_000_000,
            },
            started + Duration::from_secs(1),
        );
        assert_eq!(
            table.effective_capacity_bps_at(route, 100_000_000, started + Duration::from_secs(31),),
            10_000_000
        );
    }
}
