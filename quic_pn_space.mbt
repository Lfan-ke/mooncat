// A QUIC packet-number space (RFC 9000 §12.3): the Initial, Handshake, and Application
// spaces each number their packets independently, track which packet numbers arrived so
// they can be acknowledged, remember the largest number the peer has acknowledged, and
// note when an ack-eliciting packet is owed an ACK. This is the per-space bookkeeping
// the connection state machine composes; it holds no keys or sockets, only the numbering
// and acknowledgement state, so it is pure and testable on its own.

///|
/// One packet-number space's send/receive numbering and acknowledgement state.
pub struct PacketNumberSpace {
  mut next_pn : Int64
  received : AckRangeSet
  mut largest_acked : Int64?
  mut ack_eliciting_pending : Bool
}

///|
/// A fresh space: next packet number 0, nothing received or acknowledged.
pub fn PacketNumberSpace::new() -> PacketNumberSpace {
  {
    next_pn: 0,
    received: AckRangeSet::new(),
    largest_acked: None,
    ack_eliciting_pending: false,
  }
}

///|
/// Allocate the next packet number to send, advancing the counter.
pub fn PacketNumberSpace::next_packet_number(self : PacketNumberSpace) -> Int64 {
  let pn = self.next_pn
  self.next_pn = self.next_pn + 1L
  pn
}

///|
/// Skip the send counter past `pn`, so a packet another sender numbered in this space — the
/// recovery loop's, which keeps its own counter — is not handed out again here. A `pn` this
/// space is already past leaves it alone.
pub fn PacketNumberSpace::advance_past(
  self : PacketNumberSpace,
  pn : Int64,
) -> Unit {
  if pn >= self.next_pn {
    self.next_pn = pn + 1L
  }
}

///|
/// The largest packet number the peer has acknowledged, or `None`.
pub fn PacketNumberSpace::largest_acked(self : PacketNumberSpace) -> Int64? {
  self.largest_acked
}

///|
/// Record that packet number `pn` arrived. `ack_eliciting` marks a packet that must be
/// acknowledged (RFC 9000 §13.2.1); a pure-ACK packet is recorded but does not itself
/// oblige a new ACK.
pub fn PacketNumberSpace::on_packet_received(
  self : PacketNumberSpace,
  pn : Int64,
  ack_eliciting : Bool,
) -> Unit {
  self.received.add(pn.reinterpret_as_uint64())
  if ack_eliciting {
    self.ack_eliciting_pending = true
  }
}

///|
/// Record that the peer acknowledged up to `largest`, advancing the high-water mark
/// (an older ACK never lowers it).
pub fn PacketNumberSpace::on_ack_received(
  self : PacketNumberSpace,
  largest : Int64,
) -> Unit {
  match self.largest_acked {
    Some(current) => if largest > current { self.largest_acked = Some(largest) }
    None => self.largest_acked = Some(largest)
  }
}

///|
/// Whether an ACK is owed — an ack-eliciting packet has arrived since the last ACK was
/// built.
pub fn PacketNumberSpace::ack_pending(self : PacketNumberSpace) -> Bool {
  self.ack_eliciting_pending
}

///|
/// Build the ACK frame acknowledging everything received so far with the given
/// `ack_delay`, and clear the pending flag. `None` when nothing has been received.
pub fn PacketNumberSpace::build_ack(
  self : PacketNumberSpace,
  ack_delay : UInt64,
) -> QuicFrame? {
  match self.received.to_ack_fields() {
    Some((largest, first_range, pairs)) => {
      self.ack_eliciting_pending = false
      Some(Ack(largest~, delay=ack_delay, first_range~, ranges=pairs))
    }
    None => None
  }
}
