// The QUIC recovery loop for one packet-number space (RFC 9002): it ties the RTT estimator,
// the sent-packet tracker, and the NewReno congestion controller into the state a sender keeps
// as it puts packets on the wire and processes their acknowledgements. Sending a packet records
// it and charges the congestion window; a received ACK samples the RTT off the largest newly
// acknowledged packet, frees the acknowledged bytes, then runs loss detection — a congestion
// signal halves the window, and the lost packets' numbers come back to be retransmitted. This
// is the pure core the async UDP send loop drives.

///|
/// A sender's recovery state for one packet-number space (RFC 9002).
pub struct QuicRecovery {
  rtt : RttEstimator
  tracker : SentPacketTracker
  cc : NewReno
  max_ack_delay : Int64
  granularity : Int64
  packet_threshold : Int64
  mut pto_count : Int
  mut last_sent_time : Int64
}

///|
fn recovery_pow2(n : Int) -> Int64 {
  let mut r = 1L
  for _i = 0; _i < n; _i = _i + 1 {
    r = r * 2L
  }
  r
}

///|
/// A fresh recovery state: `max_datagram_size` sizes the congestion window, `max_ack_delay`
/// caps a peer's reported ACK delay, and `granularity` floors the timers — all microseconds
/// except the datagram size in bytes. The packet-reordering threshold is kPacketThreshold (3).
pub fn QuicRecovery::new(
  max_datagram_size : Int64,
  max_ack_delay : Int64,
  granularity : Int64,
) -> QuicRecovery {
  {
    rtt: RttEstimator::new(),
    tracker: SentPacketTracker::new(),
    cc: NewReno::new(max_datagram_size),
    max_ack_delay,
    granularity,
    packet_threshold: 3L,
    pto_count: 0,
    last_sent_time: -1L,
  }
}

///|
/// Record an ack-eliciting packet numbered `pn` sent at `now` (microseconds) carrying `size`
/// bytes: track it for acknowledgement and charge the congestion window.
pub fn QuicRecovery::on_packet_sent(
  self : QuicRecovery,
  pn : Int64,
  now : Int64,
  size : Int64,
) -> Unit {
  self.tracker.on_sent(pn, now, size)
  self.cc.on_sent(size)
  self.last_sent_time = now
}

///|
/// Process a received ACK `frame` at `now` with the peer's reported `ack_delay` (RFC 9002
/// §5–§7): sample the RTT off the largest newly acknowledged packet, free the acknowledged
/// bytes in the congestion window, then run loss detection over both thresholds. A non-empty
/// loss is one congestion signal (halving the window) and frees the lost bytes. Returns the
/// packet numbers declared lost — the frames to retransmit. Raises on a malformed ACK frame.
pub fn QuicRecovery::on_ack_received(
  self : QuicRecovery,
  frame : QuicFrame,
  now : Int64,
  ack_delay : Int64,
) -> Array[Int64] raise {
  let ranges = quic_ack_frame_ranges(frame)
  if ranges.length() == 0 {
    return []
  }
  let mut largest = -1L
  for r in ranges {
    if r.1 > largest {
      largest = r.1
    }
  }
  let prev_largest = self.tracker.largest_acked()
  let sample_time = self.tracker.time_of(largest)
  let acked_bytes = self.tracker.on_ack_ranges(ranges)
  self.cc.on_ack(acked_bytes)
  if acked_bytes > 0L {
    self.pto_count = 0
  }
  match sample_time {
    Some(ts) =>
      if largest > prev_largest {
        self.rtt.update(now - ts, ack_delay, self.max_ack_delay)
      }
    None => ()
  }
  let time_threshold = quic_loss_time_threshold(self.rtt, self.granularity)
  let lost = self.tracker.detect_lost_packets(
    now,
    self.packet_threshold,
    time_threshold,
  )
  if lost.length() > 0 {
    for p in lost {
      self.cc.on_packet_lost(p.size)
    }
    self.cc.on_congestion()
  }
  lost.map(p => p.pn)
}

///|
/// Whether `bytes` more may be sent without exceeding the congestion window.
pub fn QuicRecovery::can_send(self : QuicRecovery, bytes : Int64) -> Bool {
  self.cc.can_send(bytes)
}

///|
/// The current congestion window (bytes).
pub fn QuicRecovery::window(self : QuicRecovery) -> Int64 {
  self.cc.window()
}

///|
/// The bytes currently in flight.
pub fn QuicRecovery::in_flight(self : QuicRecovery) -> Int64 {
  self.cc.in_flight()
}

///|
/// The smoothed RTT (microseconds).
pub fn QuicRecovery::smoothed_rtt(self : QuicRecovery) -> Int64 {
  self.rtt.smoothed()
}

///|
/// The probe timeout (microseconds).
pub fn QuicRecovery::pto(self : QuicRecovery) -> Int64 {
  self.rtt.pto(self.max_ack_delay, self.granularity)
}

///|
/// The number of consecutive probe timeouts without an acknowledgement (the backoff exponent).
pub fn QuicRecovery::pto_count(self : QuicRecovery) -> Int {
  self.pto_count
}

///|
/// The time (microseconds) at which the probe timeout fires, armed from the last ack-eliciting
/// packet sent and backed off by `2^pto_count` (RFC 9002 §6.2.1). `None` when nothing is
/// outstanding — the timer is disarmed.
pub fn QuicRecovery::pto_deadline(self : QuicRecovery) -> Int64? {
  if self.tracker.outstanding().length() == 0 {
    None
  } else {
    Some(self.last_sent_time + self.pto() * recovery_pow2(self.pto_count))
  }
}

///|
/// Handle a probe timeout (RFC 9002 §6.2.4): back off the timer for the next arming. The caller
/// sends probe packets — retransmitting outstanding frames or new data.
pub fn QuicRecovery::on_pto(self : QuicRecovery) -> Unit {
  self.pto_count = self.pto_count + 1
}

///|
/// The packet numbers still outstanding.
pub fn QuicRecovery::outstanding(self : QuicRecovery) -> Array[Int64] {
  self.tracker.outstanding()
}
