// QUIC loss detection (RFC 9002 §6.1). An endpoint keeps a record of each ack-eliciting packet
// it has sent but not yet had acknowledged — its number, the time it was sent, and the bytes it
// put in flight. When an ACK arrives it drops the acknowledged records and advances the largest
// acknowledged number, then declares lost every still-outstanding packet that is either at
// least kPacketThreshold (3) packets before that largest (§6.1.1) or was sent longer than a
// time threshold ago (§6.1.2, derived from the RTT). Lost packets' frames are retransmitted.

///|
/// A sent, not-yet-acknowledged ack-eliciting packet (RFC 9002 §A.1): its number, the send
/// time in microseconds, and the bytes it counts toward the congestion window.
pub(all) struct SentPacket {
  pn : Int64
  time_sent : Int64
  size : Int64
}

///|
/// The outstanding ack-eliciting packets in one packet-number space and the largest packet
/// number acknowledged so far (-1 before any ACK).
pub struct SentPacketTracker {
  mut outstanding : Array[SentPacket]
  mut largest_acked : Int64
}

///|
/// A fresh tracker with nothing outstanding.
pub fn SentPacketTracker::new() -> SentPacketTracker {
  { outstanding: [], largest_acked: -1L }
}

///|
fn loss_contains(arr : Array[Int64], x : Int64) -> Bool {
  for v in arr {
    if v == x {
      return true
    }
  }
  false
}

///|
/// Record that an ack-eliciting packet numbered `pn` was sent at `time_sent` (microseconds)
/// carrying `size` bytes in flight.
pub fn SentPacketTracker::on_sent(
  self : SentPacketTracker,
  pn : Int64,
  time_sent : Int64,
  size : Int64,
) -> Unit {
  self.outstanding.push({ pn, time_sent, size })
}

///|
/// Process an ACK acknowledging the packet numbers `acked`: drop them from the outstanding set
/// and advance `largest_acked`. Returns the bytes newly taken out of flight.
pub fn SentPacketTracker::on_ack(
  self : SentPacketTracker,
  acked : Array[Int64],
) -> Int64 {
  let remaining : Array[SentPacket] = []
  let mut acked_bytes = 0L
  for p in self.outstanding {
    if loss_contains(acked, p.pn) {
      acked_bytes = acked_bytes + p.size
    } else {
      remaining.push(p)
    }
  }
  self.outstanding = remaining
  for pn in acked {
    if pn > self.largest_acked {
      self.largest_acked = pn
    }
  }
  acked_bytes
}

///|
/// The acknowledged packet-number ranges an ACK frame conveys, as ascending inclusive
/// `(low, high)` pairs (RFC 9000 §19.3), or an empty list for a non-ACK frame. Raises if the
/// frame's ranges underflow the packet-number space.
pub fn quic_ack_frame_ranges(frame : QuicFrame) -> Array[(Int64, Int64)] raise {
  match frame {
    Ack(largest~, first_range~, ranges~, ..) =>
      ack_fields_to_ranges(largest, first_range, ranges).map(r => {
        (r.0.reinterpret_as_int64(), r.1.reinterpret_as_int64())
      })
    _ => []
  }
}

///|
/// Process an ACK whose acknowledged packets are the ascending inclusive `ranges`: drop every
/// outstanding packet that falls in a range and advance `largest_acked`. Returns the bytes
/// newly taken out of flight — the range-based path a real ACK frame drives.
pub fn SentPacketTracker::on_ack_ranges(
  self : SentPacketTracker,
  ranges : Array[(Int64, Int64)],
) -> Int64 {
  let remaining : Array[SentPacket] = []
  let mut acked_bytes = 0L
  for p in self.outstanding {
    let mut acked = false
    for r in ranges {
      if p.pn >= r.0 && p.pn <= r.1 {
        acked = true
        break
      }
    }
    if acked {
      acked_bytes = acked_bytes + p.size
    } else {
      remaining.push(p)
    }
  }
  self.outstanding = remaining
  for r in ranges {
    if r.1 > self.largest_acked {
      self.largest_acked = r.1
    }
  }
  acked_bytes
}

///|
/// Declare lost every outstanding packet sent at least `threshold` packets before the largest
/// acknowledged (RFC 9002 §6.1.1, kPacketThreshold = 3): a packet `pn` is lost when
/// `largest_acked - pn >= threshold`. Returns the lost packet numbers and stops tracking them.
/// Nothing is lost before the first ACK.
pub fn SentPacketTracker::detect_lost(
  self : SentPacketTracker,
  threshold : Int64,
) -> Array[Int64] {
  let lost : Array[Int64] = []
  let kept : Array[SentPacket] = []
  for p in self.outstanding {
    if self.largest_acked >= 0L && self.largest_acked - p.pn >= threshold {
      lost.push(p.pn)
    } else {
      kept.push(p)
    }
  }
  self.outstanding = kept
  lost
}

///|
/// Declare lost every outstanding packet sent before the largest acknowledged and older than
/// `time_threshold` microseconds at `now` (RFC 9002 §6.1.2): lost when `largest_acked > pn` and
/// `now - time_sent >= time_threshold`. Returns the lost packet numbers and stops tracking them.
pub fn SentPacketTracker::detect_lost_time(
  self : SentPacketTracker,
  now : Int64,
  time_threshold : Int64,
) -> Array[Int64] {
  let lost : Array[Int64] = []
  let kept : Array[SentPacket] = []
  for p in self.outstanding {
    if self.largest_acked > p.pn && now - p.time_sent >= time_threshold {
      lost.push(p.pn)
    } else {
      kept.push(p)
    }
  }
  self.outstanding = kept
  lost
}

///|
/// The loss time threshold (RFC 9002 §6.1.2): `max(kTimeThreshold · max(smoothed_rtt,
/// latest_rtt), granularity)` with kTimeThreshold = 9/8, in microseconds.
pub fn quic_loss_time_threshold(
  rtt : RttEstimator,
  granularity : Int64,
) -> Int64 {
  let m = if rtt.smoothed() > rtt.latest() {
    rtt.smoothed()
  } else {
    rtt.latest()
  }
  let scaled = 9L * m / 8L
  if scaled > granularity {
    scaled
  } else {
    granularity
  }
}

///|
/// The send time (microseconds) of the outstanding packet numbered `pn`, or `None` if it is
/// not currently outstanding.
pub fn SentPacketTracker::time_of(
  self : SentPacketTracker,
  pn : Int64,
) -> Int64? {
  for p in self.outstanding {
    if p.pn == pn {
      return Some(p.time_sent)
    }
  }
  None
}

///|
/// Declare lost every outstanding packet meeting either the packet threshold (§6.1.1) or the
/// time threshold (§6.1.2), returning the lost records — with their sizes, so the caller can
/// take them out of the congestion window — and removing them from the outstanding set.
pub fn SentPacketTracker::detect_lost_packets(
  self : SentPacketTracker,
  now : Int64,
  packet_threshold : Int64,
  time_threshold : Int64,
) -> Array[SentPacket] {
  let lost : Array[SentPacket] = []
  let kept : Array[SentPacket] = []
  for p in self.outstanding {
    let by_packet = self.largest_acked >= 0L &&
      self.largest_acked - p.pn >= packet_threshold
    let by_time = self.largest_acked > p.pn &&
      now - p.time_sent >= time_threshold
    if by_packet || by_time {
      lost.push(p)
    } else {
      kept.push(p)
    }
  }
  self.outstanding = kept
  lost
}

///|
/// The packet numbers still outstanding (sent, not yet acknowledged or declared lost).
pub fn SentPacketTracker::outstanding(self : SentPacketTracker) -> Array[Int64] {
  self.outstanding.map(p => p.pn)
}

///|
/// The largest acknowledged packet number, or -1 before any ACK.
pub fn SentPacketTracker::largest_acked(self : SentPacketTracker) -> Int64 {
  self.largest_acked
}
