// QUIC loss detection by packet threshold (RFC 9002 §6.1.1). An endpoint keeps the ack-
// eliciting packets it has sent but not yet had acknowledged; when an ACK arrives it drops the
// acknowledged ones and advances the largest acknowledged packet number, then declares lost
// every still-outstanding packet sent at least kPacketThreshold (3) packets before that
// largest — those are assumed dropped rather than merely reordered, and their frames are
// retransmitted. Time-threshold loss (§6.1.2) layers on top of this with the RTT estimate.

///|
/// The outstanding ack-eliciting packets in one packet-number space and the largest packet
/// number acknowledged so far (-1 before any ACK).
pub struct SentPacketTracker {
  mut outstanding : Array[Int64]
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
/// Record that an ack-eliciting packet numbered `pn` was sent.
pub fn SentPacketTracker::on_sent(self : SentPacketTracker, pn : Int64) -> Unit {
  self.outstanding.push(pn)
}

///|
/// Process an ACK acknowledging the packet numbers `acked`: drop them from the outstanding set
/// and advance `largest_acked`. Returns how many outstanding packets this newly acknowledged.
pub fn SentPacketTracker::on_ack(
  self : SentPacketTracker,
  acked : Array[Int64],
) -> Int {
  let remaining : Array[Int64] = []
  let mut newly = 0
  for pn in self.outstanding {
    if loss_contains(acked, pn) {
      newly = newly + 1
    } else {
      remaining.push(pn)
    }
  }
  self.outstanding = remaining
  for pn in acked {
    if pn > self.largest_acked {
      self.largest_acked = pn
    }
  }
  newly
}

///|
/// Declare lost every outstanding packet sent at least `threshold` packets before the largest
/// acknowledged (RFC 9002 §6.1.1, kPacketThreshold = 3): a packet `pn` is lost when
/// `largest_acked - pn >= threshold`. Returns the lost packet numbers and stops tracking them
/// (their frames are to be retransmitted). Nothing is lost before the first ACK.
pub fn SentPacketTracker::detect_lost(
  self : SentPacketTracker,
  threshold : Int64,
) -> Array[Int64] {
  let lost : Array[Int64] = []
  let kept : Array[Int64] = []
  for pn in self.outstanding {
    if self.largest_acked >= 0L && self.largest_acked - pn >= threshold {
      lost.push(pn)
    } else {
      kept.push(pn)
    }
  }
  self.outstanding = kept
  lost
}

///|
/// The packet numbers still outstanding (sent, not yet acknowledged or declared lost).
pub fn SentPacketTracker::outstanding(self : SentPacketTracker) -> Array[Int64] {
  self.outstanding
}

///|
/// The largest acknowledged packet number, or -1 before any ACK.
pub fn SentPacketTracker::largest_acked(self : SentPacketTracker) -> Int64 {
  self.largest_acked
}
