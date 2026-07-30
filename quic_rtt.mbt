// QUIC RTT estimation (RFC 9002 §5): from each round-trip sample an endpoint keeps the
// latest, minimum, smoothed, and mean-deviation RTT, which drive the probe-timeout and loss
// thresholds of loss recovery. The first sample seeds smoothed_rtt directly and rttvar at half
// the sample; later samples fold in an exponentially weighted moving average, discounting the
// peer's reported ack delay (capped at max_ack_delay) so only propagation time is measured. All
// durations are microseconds.

///|
/// An endpoint's RTT estimate for one packet-number space (RFC 9002 §5).
pub struct RttEstimator {
  mut latest_rtt : Int64
  mut min_rtt : Int64
  mut smoothed_rtt : Int64
  mut rttvar : Int64
  mut has_sample : Bool
}

///|
/// A fresh estimator with no samples yet.
pub fn RttEstimator::new() -> RttEstimator {
  { latest_rtt: 0, min_rtt: 0, smoothed_rtt: 0, rttvar: 0, has_sample: false }
}

///|
/// Fold in a new RTT sample (RFC 9002 §5.3). `latest_rtt` is the measured round trip and
/// `ack_delay` the peer's reported delay before sending the ACK, both in microseconds;
/// `ack_delay` is capped at `max_ack_delay` and subtracted only when doing so keeps the sample
/// at or above min_rtt. The first sample seeds the estimate; later ones update the EWMA.
pub fn RttEstimator::update(
  self : RttEstimator,
  latest_rtt : Int64,
  ack_delay : Int64,
  max_ack_delay : Int64,
) -> Unit {
  self.latest_rtt = latest_rtt
  if self.has_sample {
    if latest_rtt < self.min_rtt {
      self.min_rtt = latest_rtt
    }
    let capped_delay = if ack_delay < max_ack_delay {
      ack_delay
    } else {
      max_ack_delay
    }
    let adjusted_rtt = if latest_rtt >= self.min_rtt + capped_delay {
      latest_rtt - capped_delay
    } else {
      latest_rtt
    }
    let diff = self.smoothed_rtt - adjusted_rtt
    let abs_diff = if diff < 0L { -diff } else { diff }
    self.rttvar = (3L * self.rttvar + abs_diff) / 4L
    self.smoothed_rtt = (7L * self.smoothed_rtt + adjusted_rtt) / 8L
  } else {
    self.min_rtt = latest_rtt
    self.smoothed_rtt = latest_rtt
    self.rttvar = latest_rtt / 2L
    self.has_sample = true
  }
}

///|
/// The latest RTT sample (microseconds).
pub fn RttEstimator::latest(self : RttEstimator) -> Int64 {
  self.latest_rtt
}

///|
/// The minimum RTT seen (microseconds).
pub fn RttEstimator::min(self : RttEstimator) -> Int64 {
  self.min_rtt
}

///|
/// The smoothed RTT (microseconds).
pub fn RttEstimator::smoothed(self : RttEstimator) -> Int64 {
  self.smoothed_rtt
}

///|
/// The RTT variation, the mean deviation estimate (microseconds).
pub fn RttEstimator::variation(self : RttEstimator) -> Int64 {
  self.rttvar
}

///|
/// The Probe Timeout duration (RFC 9002 §6.2.1): `smoothed_rtt + max(4·rttvar, granularity) +
/// max_ack_delay`. Before the first sample it is the initial RTT-based `2·initial_rtt`; here,
/// with no sample, it falls back to `granularity + max_ack_delay`.
pub fn RttEstimator::pto(
  self : RttEstimator,
  max_ack_delay : Int64,
  granularity : Int64,
) -> Int64 {
  let variation_term = {
    let four_var = 4L * self.rttvar
    if four_var > granularity {
      four_var
    } else {
      granularity
    }
  }
  self.smoothed_rtt + variation_term + max_ack_delay
}
