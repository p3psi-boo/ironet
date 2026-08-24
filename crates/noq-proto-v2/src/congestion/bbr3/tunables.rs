//! Runtime-adjustable BBRv3 parameters.
//!
//! Writers update the atomics and publish a new `generation`. Most parameters
//! are read and clamped at packet-timed round boundaries; a newly positive
//! live pacing cap and its quantum guard also have a packet-path fast read so
//! an already queued burst cannot escape before the next boundary.

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

const RELAXED: Ordering = Ordering::Relaxed;

fn clamp_u32(value: u32, lo: u32, hi: u32, count: &mut u64) -> u32 {
    let bounded = value.clamp(lo, hi);
    *count += u64::from(value != bounded);
    bounded
}

fn clamp_u64(value: u64, lo: u64, hi: u64, count: &mut u64) -> u64 {
    let bounded = value.clamp(lo, hi);
    *count += u64::from(value != bounded);
    bounded
}

/// Lock-free handle shared by the slow-path learner and a BBRv3 controller.
#[derive(Debug)]
#[allow(missing_docs)]
pub struct Bbr3Tunables {
    pub generation: AtomicU64,
    /// Monotonic host request to discard a standby/control-derived capacity
    /// model and enter Startup for newly observed TUN bulk demand.
    pub capacity_probe_generation: AtomicU64,
    pub probe_bw_up_pacing_gain_milli: AtomicU32,
    pub probe_bw_down_pacing_gain_milli: AtomicU32,
    pub cruise_pacing_gain_milli: AtomicU32,
    pub default_cwnd_gain_milli: AtomicU32,
    pub probe_bw_up_cwnd_gain_milli: AtomicU32,
    pub headroom_milli: AtomicU32,
    pub beta_milli: AtomicU32,
    pub loss_thresh_milli: AtomicU32,
    pub loss_is_congestion: AtomicU8,
    pub queue_delay_guard_inflation_milli: AtomicU32,
    pub queue_delay_guard_slack_micros: AtomicU64,
    pub probe_rtt_interval_millis: AtomicU64,
    pub probe_rtt_duration_millis: AtomicU64,
    pub probe_rtt_cwnd_gain_milli: AtomicU32,
    pub min_probe_wait_millis: AtomicU64,
    pub max_added_probe_wait_millis: AtomicU64,
    pub pacing_rate_cap_bytes_per_second: AtomicU64,
    pub cwnd_floor_bytes: AtomicU64,
    pub cwnd_cap_bytes: AtomicU64,
    pub startup_bw_hint_bytes_per_second: AtomicU64,
    pub clamped_writes: AtomicU64,
}

impl Default for Bbr3Tunables {
    fn default() -> Self {
        Self {
            generation: AtomicU64::new(0),
            capacity_probe_generation: AtomicU64::new(0),
            probe_bw_up_pacing_gain_milli: AtomicU32::new(1_250),
            probe_bw_down_pacing_gain_milli: AtomicU32::new(900),
            cruise_pacing_gain_milli: AtomicU32::new(1_000),
            default_cwnd_gain_milli: AtomicU32::new(2_000),
            probe_bw_up_cwnd_gain_milli: AtomicU32::new(2_250),
            headroom_milli: AtomicU32::new(150),
            beta_milli: AtomicU32::new(700),
            loss_thresh_milli: AtomicU32::new(20),
            loss_is_congestion: AtomicU8::new(0),
            queue_delay_guard_inflation_milli: AtomicU32::new(500),
            queue_delay_guard_slack_micros: AtomicU64::new(5_000),
            probe_rtt_interval_millis: AtomicU64::new(5_000),
            probe_rtt_duration_millis: AtomicU64::new(200),
            probe_rtt_cwnd_gain_milli: AtomicU32::new(500),
            min_probe_wait_millis: AtomicU64::new(2_000),
            max_added_probe_wait_millis: AtomicU64::new(1_000),
            pacing_rate_cap_bytes_per_second: AtomicU64::new(0),
            cwnd_floor_bytes: AtomicU64::new(0),
            cwnd_cap_bytes: AtomicU64::new(0),
            startup_bw_hint_bytes_per_second: AtomicU64::new(0),
            clamped_writes: AtomicU64::new(0),
        }
    }
}

impl Bbr3Tunables {
    /// Make a path-local copy of a configuration template.
    pub(crate) fn copy_from(other: &Self) -> Self {
        Self {
            generation: AtomicU64::new(other.generation.load(RELAXED)),
            capacity_probe_generation: AtomicU64::new(
                other.capacity_probe_generation.load(RELAXED),
            ),
            probe_bw_up_pacing_gain_milli: AtomicU32::new(
                other.probe_bw_up_pacing_gain_milli.load(RELAXED),
            ),
            probe_bw_down_pacing_gain_milli: AtomicU32::new(
                other.probe_bw_down_pacing_gain_milli.load(RELAXED),
            ),
            cruise_pacing_gain_milli: AtomicU32::new(other.cruise_pacing_gain_milli.load(RELAXED)),
            default_cwnd_gain_milli: AtomicU32::new(other.default_cwnd_gain_milli.load(RELAXED)),
            probe_bw_up_cwnd_gain_milli: AtomicU32::new(
                other.probe_bw_up_cwnd_gain_milli.load(RELAXED),
            ),
            headroom_milli: AtomicU32::new(other.headroom_milli.load(RELAXED)),
            beta_milli: AtomicU32::new(other.beta_milli.load(RELAXED)),
            loss_thresh_milli: AtomicU32::new(other.loss_thresh_milli.load(RELAXED)),
            loss_is_congestion: AtomicU8::new(other.loss_is_congestion.load(RELAXED)),
            queue_delay_guard_inflation_milli: AtomicU32::new(
                other.queue_delay_guard_inflation_milli.load(RELAXED),
            ),
            queue_delay_guard_slack_micros: AtomicU64::new(
                other.queue_delay_guard_slack_micros.load(RELAXED),
            ),
            probe_rtt_interval_millis: AtomicU64::new(
                other.probe_rtt_interval_millis.load(RELAXED),
            ),
            probe_rtt_duration_millis: AtomicU64::new(
                other.probe_rtt_duration_millis.load(RELAXED),
            ),
            probe_rtt_cwnd_gain_milli: AtomicU32::new(
                other.probe_rtt_cwnd_gain_milli.load(RELAXED),
            ),
            min_probe_wait_millis: AtomicU64::new(other.min_probe_wait_millis.load(RELAXED)),
            max_added_probe_wait_millis: AtomicU64::new(
                other.max_added_probe_wait_millis.load(RELAXED),
            ),
            pacing_rate_cap_bytes_per_second: AtomicU64::new(
                other.pacing_rate_cap_bytes_per_second.load(RELAXED),
            ),
            cwnd_floor_bytes: AtomicU64::new(other.cwnd_floor_bytes.load(RELAXED)),
            cwnd_cap_bytes: AtomicU64::new(other.cwnd_cap_bytes.load(RELAXED)),
            startup_bw_hint_bytes_per_second: AtomicU64::new(
                other.startup_bw_hint_bytes_per_second.load(RELAXED),
            ),
            clamped_writes: AtomicU64::new(other.clamped_writes.load(RELAXED)),
        }
    }
}

/// Controller-local, validated snapshot of [`Bbr3Tunables`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(missing_docs)]
pub struct Bbr3Params {
    pub capacity_probe_generation: u64,
    pub probe_bw_up_pacing_gain: f64,
    pub probe_bw_down_pacing_gain: f64,
    pub cruise_pacing_gain: f64,
    pub default_cwnd_gain: f64,
    pub probe_bw_up_cwnd_gain: f64,
    pub headroom: f64,
    pub beta: f64,
    pub loss_thresh: f64,
    pub loss_is_congestion: bool,
    pub queue_delay_guard_inflation: f64,
    pub queue_delay_guard_slack: Duration,
    pub probe_rtt_interval: Duration,
    pub probe_rtt_duration: Duration,
    pub probe_rtt_cwnd_gain: f64,
    pub min_probe_wait: Duration,
    pub max_added_probe_wait: Duration,
    pub pacing_rate_cap_bytes_per_second: u64,
    pub cwnd_floor_bytes: u64,
    pub cwnd_cap_bytes: u64,
    pub startup_bw_hint_bytes_per_second: u64,
}

impl Bbr3Params {
    /// Read a coherent-enough atomic snapshot and clamp every untrusted value.
    ///
    /// The generation publish protocol makes partially updated snapshots
    /// transient. At worst they last one packet-timed round and every value is
    /// independently bounded here.
    pub fn from_tunables(t: &Bbr3Tunables) -> (Self, u64) {
        let mut clamped = 0;

        let up = clamp_u32(
            t.probe_bw_up_pacing_gain_milli.load(RELAXED),
            1_050,
            1_500,
            &mut clamped,
        );
        let down = clamp_u32(
            t.probe_bw_down_pacing_gain_milli.load(RELAXED),
            700,
            950,
            &mut clamped,
        );
        let cruise = clamp_u32(
            t.cruise_pacing_gain_milli.load(RELAXED),
            950,
            1_020,
            &mut clamped,
        );
        let default_cwnd = clamp_u32(
            t.default_cwnd_gain_milli.load(RELAXED),
            1_200,
            3_000,
            &mut clamped,
        );
        let up_cwnd = clamp_u32(
            t.probe_bw_up_cwnd_gain_milli.load(RELAXED),
            1_500,
            3_500,
            &mut clamped,
        );
        let headroom = clamp_u32(t.headroom_milli.load(RELAXED), 50, 400, &mut clamped);
        let beta = clamp_u32(t.beta_milli.load(RELAXED), 500, 900, &mut clamped);
        let loss_thresh = clamp_u32(t.loss_thresh_milli.load(RELAXED), 5, 100, &mut clamped);
        let guard = clamp_u32(
            t.queue_delay_guard_inflation_milli.load(RELAXED),
            200,
            1_500,
            &mut clamped,
        );
        let probe_rtt_cwnd = clamp_u32(
            t.probe_rtt_cwnd_gain_milli.load(RELAXED),
            100,
            3_500,
            &mut clamped,
        );
        let guard_slack = clamp_u64(
            t.queue_delay_guard_slack_micros.load(RELAXED),
            2_000,
            50_000,
            &mut clamped,
        );
        let probe_interval = clamp_u64(
            t.probe_rtt_interval_millis.load(RELAXED),
            2_000,
            30_000,
            &mut clamped,
        );
        let probe_duration = clamp_u64(
            t.probe_rtt_duration_millis.load(RELAXED),
            100,
            500,
            &mut clamped,
        );
        let min_probe_wait = clamp_u64(
            t.min_probe_wait_millis.load(RELAXED),
            1_000,
            10_000,
            &mut clamped,
        );
        let max_added_probe_wait = clamp_u64(
            t.max_added_probe_wait_millis.load(RELAXED),
            0,
            5_000,
            &mut clamped,
        );

        let raw_pacing_cap = t.pacing_rate_cap_bytes_per_second.load(RELAXED);
        let pacing_cap = if raw_pacing_cap == 0 || raw_pacing_cap >= 64 * 1024 {
            raw_pacing_cap
        } else {
            clamped += 1;
            64 * 1024
        };
        let mut cwnd_floor = t.cwnd_floor_bytes.load(RELAXED);
        let raw_cwnd_cap = t.cwnd_cap_bytes.load(RELAXED);
        let cwnd_cap = if raw_cwnd_cap == 0 || raw_cwnd_cap >= 4 * 1200 {
            raw_cwnd_cap
        } else {
            clamped += 1;
            4 * 1200
        };
        if cwnd_cap > 0 && cwnd_floor > cwnd_cap {
            cwnd_floor = cwnd_cap;
            clamped += 1;
        }

        (
            Self {
                capacity_probe_generation: t.capacity_probe_generation.load(RELAXED),
                probe_bw_up_pacing_gain: f64::from(up) / 1_000.0,
                probe_bw_down_pacing_gain: f64::from(down) / 1_000.0,
                cruise_pacing_gain: f64::from(cruise) / 1_000.0,
                default_cwnd_gain: f64::from(default_cwnd) / 1_000.0,
                probe_bw_up_cwnd_gain: f64::from(up_cwnd) / 1_000.0,
                headroom: f64::from(headroom) / 1_000.0,
                beta: f64::from(beta) / 1_000.0,
                loss_thresh: f64::from(loss_thresh) / 1_000.0,
                loss_is_congestion: t.loss_is_congestion.load(RELAXED) != 0,
                queue_delay_guard_inflation: f64::from(guard) / 1_000.0,
                queue_delay_guard_slack: Duration::from_micros(guard_slack),
                probe_rtt_interval: Duration::from_millis(probe_interval),
                probe_rtt_duration: Duration::from_millis(probe_duration),
                probe_rtt_cwnd_gain: f64::from(probe_rtt_cwnd) / 1_000.0,
                min_probe_wait: Duration::from_millis(min_probe_wait),
                max_added_probe_wait: Duration::from_millis(max_added_probe_wait),
                pacing_rate_cap_bytes_per_second: pacing_cap,
                cwnd_floor_bytes: cwnd_floor,
                cwnd_cap_bytes: cwnd_cap,
                startup_bw_hint_bytes_per_second: t.startup_bw_hint_bytes_per_second.load(RELAXED),
            },
            clamped,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_existing_controller_constants() {
        let (p, clamped) = Bbr3Params::from_tunables(&Bbr3Tunables::default());
        assert_eq!(clamped, 0);
        assert_eq!(p.probe_bw_up_pacing_gain, 1.25);
        assert_eq!(p.probe_bw_down_pacing_gain, 0.9);
        assert_eq!(p.cruise_pacing_gain, 1.0);
        assert_eq!(p.default_cwnd_gain, 2.0);
        assert_eq!(p.probe_bw_up_cwnd_gain, 2.25);
        assert_eq!(p.headroom, 0.15);
        assert_eq!(p.beta, 0.7);
        assert_eq!(p.loss_thresh, 0.02);
        assert!(!p.loss_is_congestion);
        assert_eq!(p.queue_delay_guard_inflation, 0.5);
        assert_eq!(p.queue_delay_guard_slack, Duration::from_millis(5));
        assert_eq!(p.probe_rtt_interval, Duration::from_secs(5));
        assert_eq!(p.probe_rtt_duration, Duration::from_millis(200));
        assert_eq!(p.probe_rtt_cwnd_gain, 0.5);
        assert_eq!(p.min_probe_wait, Duration::from_secs(2));
        assert_eq!(p.max_added_probe_wait, Duration::from_secs(1));
    }

    #[test]
    fn untrusted_values_are_clamped_and_counted() {
        let t = Bbr3Tunables::default();
        t.probe_bw_up_pacing_gain_milli.store(1, RELAXED);
        t.loss_thresh_milli.store(u32::MAX, RELAXED);
        t.pacing_rate_cap_bytes_per_second.store(1, RELAXED);
        t.cwnd_floor_bytes.store(20_000, RELAXED);
        t.cwnd_cap_bytes.store(2_000, RELAXED);
        let (p, clamped) = Bbr3Params::from_tunables(&t);
        assert_eq!(p.probe_bw_up_pacing_gain, 1.05);
        assert_eq!(p.loss_thresh, 0.1);
        assert_eq!(p.pacing_rate_cap_bytes_per_second, 64 * 1024);
        assert_eq!(p.cwnd_cap_bytes, 4_800);
        assert_eq!(p.cwnd_floor_bytes, 4_800);
        assert_eq!(clamped, 5);
    }
}
