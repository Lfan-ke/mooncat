// Packet-number-space bookkeeping (RFC 9000 §12.3, §13.2): monotonic send numbering,
// recording received packets, ACK generation and the ack-pending flag, and the largest
// acknowledged high-water mark.

///|
test "pn space: send numbers are monotonic from zero" {
  let s = PacketNumberSpace::new()
  assert_eq(s.next_packet_number(), 0)
  assert_eq(s.next_packet_number(), 1)
  assert_eq(s.next_packet_number(), 2)
}

///|
test "pn space: an ack-eliciting packet owes an ACK; building it clears the flag" {
  let s = PacketNumberSpace::new()
  assert_eq(s.ack_pending(), false)
  s.on_packet_received(0, true)
  s.on_packet_received(1, true)
  s.on_packet_received(2, true)
  assert_eq(s.ack_pending(), true)
  match s.build_ack(0) {
    Some(Ack(largest~, first_range~, ranges~, ..)) => {
      assert_eq(largest, 2)
      assert_eq(first_range, 2) // 0..2 contiguous below the largest
      assert_eq(ranges, [])
    }
    _ => abort("expected an ACK frame")
  }
  assert_eq(s.ack_pending(), false)
}

///|
test "pn space: a pure-ACK packet is recorded but owes no new ACK" {
  let s = PacketNumberSpace::new()
  s.on_packet_received(0, false) // not ack-eliciting
  assert_eq(s.ack_pending(), false)
  // It is still acknowledged when an ACK is eventually built.
  match s.build_ack(5) {
    Some(Ack(largest~, delay~, ..)) => {
      assert_eq(largest, 0)
      assert_eq(delay, 5)
    }
    _ => abort("expected an ACK frame")
  }
}

///|
test "pn space: no ACK is built before anything is received" {
  let s = PacketNumberSpace::new()
  assert_eq(s.build_ack(0), None)
}

///|
test "pn space: largest acknowledged only advances" {
  let s = PacketNumberSpace::new()
  assert_eq(s.largest_acked(), None)
  s.on_ack_received(5)
  assert_eq(s.largest_acked(), Some(5))
  s.on_ack_received(3) // an older ACK does not lower it
  assert_eq(s.largest_acked(), Some(5))
  s.on_ack_received(9)
  assert_eq(s.largest_acked(), Some(9))
}

///|
test "pn space: a gap in received packets produces a multi-range ACK" {
  let s = PacketNumberSpace::new()
  for pn in [0, 1, 3] {
    s.on_packet_received(pn.to_int64(), true)
  }
  match s.build_ack(0) {
    Some(Ack(largest~, first_range~, ranges~, ..)) => {
      assert_eq(largest, 3)
      assert_eq(first_range, 0) // only 3 in the top range
      assert_eq(ranges, [(0, 1)]) // gap 0, then 0..1
    }
    _ => abort("expected an ACK frame")
  }
}
