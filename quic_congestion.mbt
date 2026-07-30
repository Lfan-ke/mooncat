// QUIC congestion control, NewReno (RFC 9002 §7). The controller bounds how many bytes may be
// in flight by a congestion window that grows on acknowledgement and halves on congestion.
// Below the slow-start threshold the window grows by every acknowledged byte (exponential per
// round trip); at or above it, growth is one max-datagram-size per window of acknowledged data
// (additive). A congestion signal — a lost packet or ECN — sets the threshold to half the
// window and drops the window to it, floored at two datagrams. All sizes are bytes.

///|
/// A NewReno congestion controller for one connection (RFC 9002 §7).
pub struct NewReno {
  mut cwnd : Int64
  mut ssthresh : Int64
  mut bytes_in_flight : Int64
  max_datagram_size : Int64
}

///|
/// A fresh controller (RFC 9002 §7.2): the initial window is
/// `min(10·max_datagram_size, max(2·max_datagram_size, 14720))`, the slow-start threshold is
/// effectively unbounded, and nothing is in flight.
pub fn NewReno::new(max_datagram_size : Int64) -> NewReno {
  let two = 2L * max_datagram_size
  let ten = 10L * max_datagram_size
  let floor = if two > 14720L { two } else { 14720L }
  let initial = if ten < floor { ten } else { floor }
  { cwnd: initial, ssthresh: 1L << 60, bytes_in_flight: 0L, max_datagram_size }
}

///|
/// Record `bytes` of a packet sent into flight.
pub fn NewReno::on_sent(self : NewReno, bytes : Int64) -> Unit {
  self.bytes_in_flight = self.bytes_in_flight + bytes
}

///|
/// Acknowledge `acked_bytes` of newly acknowledged data (RFC 9002 §7.3.1–§7.3.2): take it out
/// of flight, then grow the window — by the acknowledged bytes in slow start, or by
/// `max_datagram_size · acked_bytes / cwnd` in congestion avoidance.
pub fn NewReno::on_ack(self : NewReno, acked_bytes : Int64) -> Unit {
  self.bytes_in_flight = if self.bytes_in_flight > acked_bytes {
    self.bytes_in_flight - acked_bytes
  } else {
    0L
  }
  if self.cwnd < self.ssthresh {
    self.cwnd = self.cwnd + acked_bytes
  } else {
    self.cwnd = self.cwnd + self.max_datagram_size * acked_bytes / self.cwnd
  }
}

///|
/// Take `lost_bytes` of a declared-lost packet out of flight (RFC 9002 §7.3): the window
/// reduction itself is a single `on_congestion` per recovery period.
pub fn NewReno::on_packet_lost(self : NewReno, lost_bytes : Int64) -> Unit {
  self.bytes_in_flight = if self.bytes_in_flight > lost_bytes {
    self.bytes_in_flight - lost_bytes
  } else {
    0L
  }
}

///|
/// Enter a recovery period on a congestion signal (RFC 9002 §7.3.2): halve the window to the
/// new slow-start threshold, floored at the minimum window of two datagrams.
pub fn NewReno::on_congestion(self : NewReno) -> Unit {
  self.ssthresh = self.cwnd / 2L
  let min_window = 2L * self.max_datagram_size
  self.cwnd = if self.ssthresh > min_window {
    self.ssthresh
  } else {
    min_window
  }
}

///|
/// Whether `bytes` more may be sent without exceeding the congestion window.
pub fn NewReno::can_send(self : NewReno, bytes : Int64) -> Bool {
  self.bytes_in_flight + bytes <= self.cwnd
}

///|
/// The congestion window (bytes).
pub fn NewReno::window(self : NewReno) -> Int64 {
  self.cwnd
}

///|
/// The slow-start threshold (bytes).
pub fn NewReno::ssthresh(self : NewReno) -> Int64 {
  self.ssthresh
}

///|
/// The bytes currently in flight.
pub fn NewReno::in_flight(self : NewReno) -> Int64 {
  self.bytes_in_flight
}
