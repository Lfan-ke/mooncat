// The composed QUIC recovery loop (RFC 9002): RTT sampling, congestion control, and loss
// detection driven by sends and ACKs. Times are microseconds, sizes bytes.

///|
test "recovery: an ACK samples the RTT, frees bytes, and grows the window with no loss" {
  let rec = QuicRecovery::new(1200L, 25000L, 1000L)
  rec.on_packet_sent(0L, 0L, 1200L)
  assert_eq(rec.in_flight(), 1200L)
  // ACK for packet 0 at now = 100 µs.
  let ack : QuicFrame = Ack(largest=0UL, delay=0UL, first_range=0UL, ranges=[])
  assert_eq(rec.on_ack_received(ack, 100L, 0L), [])
  // RTT sample 100; the byte is freed and slow start grows the window.
  assert_eq(rec.smoothed_rtt(), 100L)
  assert_eq(rec.in_flight(), 0L)
  assert_eq(rec.window(), 13200L)
  assert_eq(rec.outstanding(), [])
}

///|
test "recovery: an ACK detects loss by both thresholds and halves the window once" {
  let rec = QuicRecovery::new(1200L, 25000L, 1000L)
  // Four packets: 0,1,2 spaced out, 3 sent just before the ACK.
  rec.on_packet_sent(0L, 0L, 1200L)
  rec.on_packet_sent(1L, 1000L, 1200L)
  rec.on_packet_sent(2L, 2000L, 1200L)
  rec.on_packet_sent(3L, 2400L, 1200L)
  assert_eq(rec.in_flight(), 4800L)
  // ACK acknowledges only packet 3 at now = 2500 µs.
  let ack : QuicFrame = Ack(largest=3UL, delay=0UL, first_range=0UL, ranges=[])
  // Packet 0 is lost by the packet threshold (3 - 0 >= 3); packet 1 by the time threshold
  // (smoothed_rtt 100 → time threshold 1000, and 2500 - 1000 >= 1000); packet 2 is too recent
  // (2500 - 2000 = 500 < 1000) and survives.
  assert_eq(rec.on_ack_received(ack, 2500L, 0L), [0L, 1L])
  assert_eq(rec.outstanding(), [2L])
  assert_eq(rec.smoothed_rtt(), 100L) // 2500 - 2400
  // Window halves once: on_ack grew 12000→13200, congestion halves to 6600.
  assert_eq(rec.window(), 6600L)
  // In flight: 4800 - 1200 (acked 3) - 2400 (lost 0,1) = 1200 (only packet 2).
  assert_eq(rec.in_flight(), 1200L)
}

///|
test "recovery: can_send tracks the window against bytes in flight" {
  let rec = QuicRecovery::new(1200L, 25000L, 1000L) // window 12000
  assert_eq(rec.can_send(1200L), true)
  for pn = 0L; pn < 10L; pn = pn + 1L {
    rec.on_packet_sent(pn, pn, 1200L)
  }
  assert_eq(rec.in_flight(), 12000L)
  assert_eq(rec.can_send(1L), false)
}
