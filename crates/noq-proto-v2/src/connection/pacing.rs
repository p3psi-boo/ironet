//! Pacing of packet transmissions.

use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
#[derive(Debug)]
pub(super) struct Pacer {
    capacity: u64,
    /// Last live congestion-controller burst quantum. Changes settle elapsed
    /// credit into the new bucket exactly once, so a live quantum adjustment
    /// neither loses earned rate nor reuses stale idle time after depletion.
    last_controller_capacity: Option<u64>,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
    /// At most one datagram of controller-rate refill overflow retained for
    /// the current wake epoch. This compensates timer lateness without
    /// allowing idle elapsed time to refill a second full quantum.
    late_refill_credit: u64,
    max_bytes_per_second: Option<u64>,
    prev: Instant,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(
        smoothed_rtt: Duration,
        window: u64,
        mtu: u16,
        max_bytes_per_second: Option<u64>,
        now: Instant,
    ) -> Self {
        let window = rate_limited_window(smoothed_rtt, window, max_bytes_per_second);
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_controller_capacity: None,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            late_refill_credit: 0,
            max_bytes_per_second,
            prev: now,
        }
    }

    /// Obtains the `max_bytes_per_second` used when this [`Pacer`] was constructed.
    pub(crate) fn max_bytes_per_second(&self) -> Option<u64> {
        self.max_bytes_per_second
    }

    /// Refill the burst budget when a warm backup becomes the active path.
    pub(super) fn on_path_activated(&mut self) {
        self.tokens = self.capacity;
        self.late_refill_credit = 0;
    }

    /// Forget elapsed refill time while a transmit was waiting for the shared
    /// UDP socket to become writable.
    ///
    /// Packet construction has already charged the bucket. Anchoring it at
    /// the actual socket flush prevents that blocked interval from refilling
    /// a second adjacent quantum immediately after the buffered batch.
    pub(super) fn on_socket_transmit_flush(&mut self, now: Instant) {
        if now.checked_duration_since(self.prev).is_some() {
            self.prev = now;
            self.late_refill_credit = 0;
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        let packet_length = u64::from(packet_length);
        let from_tokens = self.tokens.min(packet_length);
        self.tokens -= from_tokens;
        self.late_refill_credit = self
            .late_refill_credit
            .saturating_sub(packet_length - from_tokens);
    }

    /// Return how long we need to wait before sending `bytes_to_send`.
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns
    /// `Some(d)`, where `d` is the duration after which this function should be called
    /// again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF
    /// RFC for QUIC.
    ///
    /// `capacity` (bytes) and `pacing_rate` (bytes/s) are optional overrides supplied by
    /// the congestion controller (e.g. BBRv3's `send_quantum` / `pacing_rate`). They take
    /// precedence over the window-derived defaults, but are still subject to the static
    /// `max_bytes_per_second` cap configured at construction time.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
        capacity: Option<u64>,
        pacing_rate: Option<u64>,
    ) -> Option<Duration> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        let window = rate_limited_window(smoothed_rtt, window, self.max_bytes_per_second);
        if window != self.last_window || mtu != self.last_mtu {
            self.capacity = optimal_capacity(smoothed_rtt, window, mtu);

            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.late_refill_credit = 0;
            self.last_window = window;
            self.last_mtu = mtu;
        }

        let previous_capacity = self.capacity;
        let mut controller_capacity_changed = false;
        if let Some(capacity) = capacity {
            // A controller quantum is a burst budget, but it must never be smaller than
            // one packet or the token bucket could permanently reject that packet.
            let capacity = capacity.max(bytes_to_send).max(u64::from(mtu));
            controller_capacity_changed = self.last_controller_capacity != Some(capacity);
            self.last_controller_capacity = Some(capacity);
            self.capacity = capacity;
            self.tokens = self.capacity.min(self.tokens);
            if controller_capacity_changed {
                self.late_refill_credit = 0;
            }
        } else {
            self.last_controller_capacity = None;
            self.late_refill_credit = 0;
        }

        // Preserve the legacy window-derived pacer's fast path. A
        // controller-rate bucket must always settle elapsed time, even while
        // full: otherwise it can spend the old bucket after an idle interval
        // and then refill from that same interval for a second adjacent burst.
        if pacing_rate.is_none() && self.tokens >= bytes_to_send && !controller_capacity_changed {
            return None;
        }

        // We disable the legacy window-derived pacer for extremely large windows. A
        // controller-supplied rate remains authoritative regardless of cwnd size.
        if pacing_rate.is_none() && window > u64::from(u32::MAX) {
            return None;
        }

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        let refill_rate = match pacing_rate {
            Some(rate) => self
                .max_bytes_per_second
                .map_or(rate, |limit| rate.min(limit)) as f64,
            None if !smoothed_rtt.is_zero() => window as f64 * 1.25 / smoothed_rtt.as_secs_f64(),
            None => return None,
        };
        if refill_rate <= 0.0 {
            return (self.tokens < bytes_to_send).then_some(Duration::MAX);
        }

        let new_tokens = (refill_rate * time_elapsed.as_secs_f64()).round() as u64;
        let available = self.tokens.saturating_add(new_tokens);
        if controller_capacity_changed {
            // First settle elapsed time under the old bucket's bound, then
            // resize. Idle time while the old bucket was already full must not
            // populate newly added capacity or survive a shrink as a second
            // burst.
            self.tokens = available.min(previous_capacity).min(self.capacity);
        } else {
            self.tokens = available.min(self.capacity);
        }

        // A controller timer can wake slightly after the nominal quantum
        // interval. Retain at most one datagram of the resulting overflow for
        // this wake epoch. Because elapsed time is settled and `prev` advances
        // even while the main bucket is full, idle time can never be reused
        // to create a second quantum.
        if pacing_rate.is_some() && new_tokens > 0 && !controller_capacity_changed {
            self.late_refill_credit = available.saturating_sub(self.capacity).min(u64::from(mtu));
        }

        // Controller pacing consumes the elapsed interval even if the bucket
        // was already full, so that idle time cannot be reused after the
        // bucket is depleted. Preserve the legacy sub-token accumulation for
        // the window-derived pacer.
        if pacing_rate.is_some() || new_tokens > 0 {
            self.prev = now;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens.saturating_add(self.late_refill_credit) >= bytes_to_send {
            return None;
        }

        // Wait until a full burst quantum is available. This amortizes wakeups without
        // changing the long-term byte rate; unrelated endpoint activity may wake us
        // earlier and consume a partially refilled packet's worth of tokens.
        let deficit = bytes_to_send
            .max(self.capacity)
            .saturating_sub(self.tokens.saturating_add(self.late_refill_credit));
        Some(Duration::from_secs_f64(deficit as f64 / refill_rate))
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. The controller-rate path retains
/// at most one MTU of late-wakeup refill credit; larger excess is deliberately
/// discarded so timer lateness cannot create an unbounded adjacent burst.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);
    let mtu = u64::from(mtu);

    let target_capacity = ((window as u128 * TARGET_BURST_INTERVAL.as_nanos()) / rtt) as u64;
    // Never restrict capacity below one MTU.
    let max_capacity = Ord::max(
        ((window as u128 * MAX_BURST_INTERVAL.as_nanos()) / rtt) as u64,
        mtu,
    );

    // Batch the greater of `TARGET_BURST_INTERVAL` or `MIN_BURST_SIZE` worth of traffic at a
    // time. To avoid inducing excessive latency, limit that result to at most `MAX_BURST_INTERVAL`
    // worth of traffic.
    Ord::min(
        max_capacity,
        target_capacity.clamp(MIN_BURST_SIZE * mtu, MAX_BURST_SIZE * mtu),
    )
}

/// Clamps the window to limit the sending rate to `max_bytes_per_second`.
///
/// If `max_bytes_per_second` is `None`, the original window is returned.
fn rate_limited_window(
    smoothed_rtt: Duration,
    window: u64,
    max_bytes_per_second: Option<u64>,
) -> u64 {
    let Some(max_bytes_per_second) = max_bytes_per_second else {
        return window;
    };

    let rate_window = max_bytes_per_second as f64 * smoothed_rtt.as_secs_f64();

    // the pacer refills tokens at x1.25 speed, so we shrink the window to cancel out the speedup
    // (otherwise the actual sending rate could be higher than `max_bytes_per_second`)
    let adjusted_rate_window = (rate_window / 1.25).round();

    Ord::min(window, Ord::max(adjusted_rate_window as u64, 1))
}

/// Period of traffic to batch together on a reasonably fast connection
const TARGET_BURST_INTERVAL: Duration = Duration::from_millis(2);

/// Maximum period of traffic to batch together on a slow connection
///
/// Takes precedence over [`MIN_BURST_SIZE`].
const MAX_BURST_INTERVAL: Duration = Duration::from_millis(10);

/// Minimum number of datagrams to batch together, so long as we won't have to wait for more than
/// [`MAX_BURST_INTERVAL`]
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(
                    Duration::from_micros(0),
                    0,
                    1500,
                    1,
                    old_instant,
                    None,
                    None
                )
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(
                    Duration::from_micros(0),
                    1600,
                    1500,
                    1,
                    old_instant,
                    None,
                    None
                )
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, None, new_instant)
                .delay(
                    Duration::from_micros(0),
                    1500,
                    1500,
                    3000,
                    old_instant,
                    None,
                    None
                )
                .is_none()
        );
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, None, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, None, now);
        assert_eq!(pacer.capacity, mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now, None, None);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, now, None, None);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, now, None, None);
        assert_eq!(
            pacer.capacity,
            (window as u128 * TARGET_BURST_INTERVAL.as_nanos() / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, now, None, None);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, None, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant, None, None),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((TARGET_BURST_INTERVAL.as_nanos() * 4 / 5) as u64);

        let actual_delay = pacer
            .delay(rtt, mtu as u64, mtu, window, old_instant, None, None)
            .expect("Send must be delayed");

        let diff = actual_delay.abs_diff(pace_duration);

        // Allow up to 2ns difference due to rounding
        assert!(
            diff < Duration::from_nanos(2),
            "expected ≈ {pace_duration:?}, got {actual_delay:?} (diff {diff:?})"
        );
        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration / 2,
                None,
                None,
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant, None, None),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration * 3 / 2,
                None,
                None,
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn computes_pause_correctly_for_rate_limited() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, Some(2_000), old_instant);
        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, window, old_instant, None, None),
            None,
            "When capacity is available packets should be sent immediately"
        );
        pacer.on_transmit(mtu);

        let actual_delay = pacer
            .delay(rtt, 1_000, mtu, window, old_instant, None, None)
            .expect("Send must be delayed");

        let expected_delay = Duration::from_millis(500);
        let diff = actual_delay.abs_diff(expected_delay);

        // Allow up to 2ns difference due to rounding
        assert!(
            diff < Duration::from_nanos(2),
            "expected ≈ {expected_delay:?}, got {actual_delay:?} (diff {diff:?})"
        );

        // Should be able to send after a while
        let now = old_instant + expected_delay / 2;
        assert_eq!(pacer.delay(rtt, 500, mtu, window, now, None, None), None);
    }

    #[test]
    fn controller_rate_refills_the_quantum_instead_of_falling_back_to_cwnd() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        for _ in 0..2 {
            assert_eq!(
                pacer.delay(rtt, 1_000, mtu, window, start, Some(2_000), Some(100_000)),
                None
            );
            pacer.on_transmit(mtu);
        }

        assert_eq!(pacer.tokens, 0);
        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, window, start, Some(2_000), Some(100_000)),
            Some(Duration::from_millis(20))
        );
        assert_eq!(
            pacer.delay(
                rtt,
                1_000,
                mtu,
                window,
                start + Duration::from_millis(10),
                Some(2_000),
                Some(100_000),
            ),
            None,
            "an unrelated wakeup may spend one packet of partial token credit"
        );
        assert_eq!(pacer.tokens, 1_000);
    }

    #[test]
    fn late_controller_wakeup_retains_at_most_one_datagram_of_credit() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        for _ in 0..2 {
            assert_eq!(
                pacer.delay(rtt, 1_000, mtu, window, start, Some(2_000), Some(100_000)),
                None
            );
            pacer.on_transmit(mtu);
        }

        // The 20 ms quantum timer wakes at least one packet late. The bucket
        // retains exactly one MTU beyond its ordinary quantum.
        let late = start + Duration::from_millis(40);
        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, window, late, Some(2_000), Some(100_000)),
            None
        );
        assert_eq!(pacer.tokens, 2_000);
        assert_eq!(pacer.late_refill_credit, 1_000);
        for _ in 0..3 {
            pacer.on_transmit(mtu);
        }

        // The elapsed interval was consumed even though it overflowed, so a
        // fourth packet cannot reuse it at the same timestamp.
        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, window, late, Some(2_000), Some(100_000)),
            Some(Duration::from_millis(20))
        );
        assert_eq!(pacer.tokens, 0);
    }

    #[test]
    fn very_late_wakeup_sends_at_most_q12_plus_one_mtu_at_the_same_instant() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);
        let capacity = 12_000;
        let pacing_rate = 12_000_000;

        for _ in 0..12 {
            assert_eq!(
                pacer.delay(
                    rtt,
                    1_000,
                    mtu,
                    window,
                    start,
                    Some(capacity),
                    Some(pacing_rate),
                ),
                None
            );
            pacer.on_transmit(mtu);
        }

        // Even a wake one hundred quantum intervals late may make only the
        // twelve-packet controller quantum plus one MTU available.
        let very_late = start + Duration::from_millis(100);
        let mut sent = 0;
        while pacer
            .delay(
                rtt,
                1_000,
                mtu,
                window,
                very_late,
                Some(capacity),
                Some(pacing_rate),
            )
            .is_none()
        {
            pacer.on_transmit(mtu);
            sent += u64::from(mtu);
            assert!(
                sent <= capacity + u64::from(mtu),
                "one Instant exceeded q12 plus one MTU"
            );
        }
        assert_eq!(sent, capacity + u64::from(mtu));
        assert_eq!(pacer.tokens, 0);
        assert_eq!(pacer.late_refill_credit, 0);
        assert_eq!(
            pacer.delay(
                rtt,
                1_000,
                mtu,
                window,
                very_late,
                Some(capacity),
                Some(pacing_rate),
            ),
            Some(Duration::from_millis(1))
        );
    }

    #[test]
    fn full_controller_bucket_across_ten_intervals_is_bounded_by_quantum_plus_mtu() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);
        let capacity = 2_000;
        let pacing_rate = 100_000;
        let after_ten_intervals = start + Duration::from_millis(200);

        // Publish the controller quantum before the idle interval; the
        // bucket itself remains full.
        assert_eq!(
            pacer.delay(
                rtt,
                1_000,
                mtu,
                window,
                start,
                Some(capacity),
                Some(pacing_rate),
            ),
            None
        );

        let mut sent = 0;
        while pacer
            .delay(
                rtt,
                1_000,
                mtu,
                window,
                after_ten_intervals,
                Some(capacity),
                Some(pacing_rate),
            )
            .is_none()
        {
            pacer.on_transmit(mtu);
            sent += u64::from(mtu);
            assert!(sent <= capacity + u64::from(mtu));
        }
        assert_eq!(sent, capacity + u64::from(mtu));
    }

    #[test]
    fn partial_controller_bucket_plus_one_interval_is_bounded_by_quantum_plus_mtu() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);
        let capacity = 4_000;
        let pacing_rate = 100_000;

        // Leave two MTUs in the old bucket.
        for _ in 0..2 {
            assert_eq!(
                pacer.delay(
                    rtt,
                    1_000,
                    mtu,
                    window,
                    start,
                    Some(capacity),
                    Some(pacing_rate),
                ),
                None
            );
            pacer.on_transmit(mtu);
        }

        let after_one_interval = start + Duration::from_millis(40);
        let mut sent = 0;
        while pacer
            .delay(
                rtt,
                1_000,
                mtu,
                window,
                after_one_interval,
                Some(capacity),
                Some(pacing_rate),
            )
            .is_none()
        {
            pacer.on_transmit(mtu);
            sent += u64::from(mtu);
            assert!(sent <= capacity + u64::from(mtu));
        }
        assert_eq!(sent, capacity + u64::from(mtu));
    }

    #[test]
    fn smaller_live_controller_quantum_clamps_old_burst_tokens_on_next_delay() {
        let window = 2_000_000;
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        assert_eq!(
            pacer.delay(
                rtt,
                mtu.into(),
                mtu,
                window,
                start,
                Some(64_000),
                Some(20_000_000),
            ),
            None
        );
        assert_eq!(pacer.capacity, 64_000);

        assert_eq!(
            pacer.delay(
                rtt,
                mtu.into(),
                mtu,
                window,
                start,
                Some(13_000),
                Some(13_000_000),
            ),
            None
        );
        assert_eq!(pacer.capacity, 13_000);
        assert_eq!(pacer.tokens, 13_000);
    }

    #[test]
    fn live_controller_quantum_change_settles_old_idle_time_once() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();

        for new_capacity in [1_000, 3_000] {
            let mut pacer = Pacer::new(rtt, window, mtu, None, start);
            assert_eq!(
                pacer.delay(rtt, 1_000, mtu, window, start, Some(2_000), Some(100_000)),
                None
            );

            // Leave the old bucket full across a long idle interval. Changing
            // either down or up settles under the old bound and then resizes,
            // but must not retain that interval for a second refill after the
            // converted tokens are spent.
            let changed_at = start + Duration::from_secs(1);
            assert_eq!(
                pacer.delay(
                    rtt,
                    1_000,
                    mtu,
                    window,
                    changed_at,
                    Some(new_capacity),
                    Some(100_000),
                ),
                None
            );
            assert_eq!(pacer.tokens, new_capacity.min(2_000));

            while pacer.tokens >= u64::from(mtu) {
                pacer.on_transmit(mtu);
            }
            assert_eq!(pacer.tokens, 0);
            assert_eq!(
                pacer.delay(
                    rtt,
                    1_000,
                    mtu,
                    window,
                    changed_at,
                    Some(new_capacity),
                    Some(100_000),
                ),
                Some(Duration::from_millis(new_capacity / 100)),
                "the new quantum must wait for its own refill interval"
            );
        }
    }

    #[test]
    fn live_controller_quantum_micro_adjustments_preserve_elapsed_credit() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        for _ in 0..2 {
            assert_eq!(
                pacer.delay(rtt, 1_000, mtu, window, start, Some(2_000), Some(100_000)),
                None
            );
            pacer.on_transmit(mtu);
        }
        assert_eq!(pacer.tokens, 0);

        // A live rate estimate can move the computed send quantum by one byte
        // on every poll. Each adjustment must settle, rather than erase, the
        // 500 bytes earned since the previous poll.
        for (elapsed_millis, capacity, expected_tokens) in
            [(10, 2_001, 1_000), (15, 2_002, 1_500), (20, 2_003, 2_000)]
        {
            let now = start + Duration::from_millis(elapsed_millis);
            let delay = pacer.delay(rtt, 1_000, mtu, window, now, Some(capacity), Some(100_000));
            assert_eq!(pacer.tokens, expected_tokens);
            assert_eq!(delay, None);
        }
    }

    #[test]
    fn unchanged_live_controller_quantum_bounds_overflow_credit_to_one_mtu() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        for _ in 0..2 {
            assert_eq!(
                pacer.delay(rtt, 1_000, mtu, window, start, Some(2_000), Some(100_000)),
                None
            );
            pacer.on_transmit(mtu);
        }

        let late = start + Duration::from_millis(40);
        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, window, late, Some(2_000), Some(100_000)),
            None
        );
        assert_eq!(pacer.tokens, 2_000);
        assert_eq!(pacer.late_refill_credit, 1_000);
        for _ in 0..3 {
            pacer.on_transmit(mtu);
        }
        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, window, late, Some(2_000), Some(100_000)),
            Some(Duration::from_millis(20)),
            "an unchanged quantum must retain no more than one MTU"
        );
    }

    #[test]
    fn pending_socket_send_reanchors_flush_and_requires_a_new_quantum_delay() {
        #[derive(Debug)]
        struct PendingOnceSender {
            pending: bool,
            now: Instant,
        }

        impl PendingOnceSender {
            fn poll_send(&mut self) -> std::task::Poll<()> {
                if self.pending {
                    self.pending = false;
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            }
        }

        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let capacity = 12_000;
        let pacing_rate = 12_000_000;
        let mut pacer = Pacer::new(rtt, window, mtu, None, start);

        // Protocol packet construction charges the complete old q12 GSO batch
        // before the runtime discovers socket backpressure.
        for _ in 0..12 {
            assert_eq!(
                pacer.delay(
                    rtt,
                    u64::from(mtu),
                    mtu,
                    window,
                    start,
                    Some(capacity),
                    Some(pacing_rate),
                ),
                None
            );
            pacer.on_transmit(mtu);
        }
        assert_eq!(pacer.tokens, 0);

        let mut sender = PendingOnceSender {
            pending: true,
            now: start,
        };
        assert_eq!(sender.poll_send(), std::task::Poll::Pending);
        sender.now += Duration::from_millis(100);
        assert_eq!(sender.poll_send(), std::task::Poll::Ready(()));

        // A successful retry re-anchors the pacer at the actual flush. The old
        // q12 is the only batch eligible at this timestamp; a new batch needs
        // one positive quantum interval.
        pacer.on_socket_transmit_flush(sender.now);
        assert_eq!(
            pacer.delay(
                rtt,
                u64::from(mtu),
                mtu,
                window,
                sender.now,
                Some(capacity),
                Some(pacing_rate),
            ),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            pacer.delay(
                rtt,
                u64::from(mtu),
                mtu,
                window,
                sender.now + Duration::from_millis(1),
                Some(capacity),
                Some(pacing_rate),
            ),
            None
        );
    }

    #[test]
    fn static_rate_limit_caps_a_controller_rate() {
        let window = 2_000_000;
        let mtu = 1_000;
        let rtt = Duration::from_millis(50);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, Some(50_000), start);

        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, window, start, Some(1_000), Some(100_000)),
            None
        );
        pacer.on_transmit(mtu);
        assert_eq!(
            pacer.delay(rtt, 1_000, mtu, window, start, Some(1_000), Some(100_000)),
            Some(Duration::from_millis(20))
        );
    }
}
