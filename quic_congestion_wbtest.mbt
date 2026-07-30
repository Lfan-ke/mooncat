// QUIC NewReno congestion control (RFC 9002 §7).

///|
test "congestion: the initial window is min(10·mds, max(2·mds, 14720)) (RFC 9002 §7.2)" {
  // mds 1200: min(12000, max(2400, 14720)) = min(12000, 14720) = 12000.
  assert_eq(NewReno::new(1200L).window(), 12000L)
  // mds 1500: min(15000, max(3000, 14720)) = min(15000, 14720) = 14720.
  assert_eq(NewReno::new(1500L).window(), 14720L)
}

///|
test "congestion: slow start grows the window by the acknowledged bytes" {
  let cc = NewReno::new(1200L)
  cc.on_sent(1200L)
  assert_eq(cc.in_flight(), 1200L)
  cc.on_ack(1200L) // below ssthresh → slow start
  assert_eq(cc.window(), 13200L)
  assert_eq(cc.in_flight(), 0L)
}

///|
test "congestion: a congestion signal halves the window to the new ssthresh" {
  let cc = NewReno::new(1200L)
  cc.on_ack(1200L) // window 13200
  cc.on_congestion()
  assert_eq(cc.ssthresh(), 6600L) // 13200 / 2
  assert_eq(cc.window(), 6600L)
  // At ssthresh now, further acks use congestion avoidance: cwnd += mds·acked/cwnd.
  cc.on_ack(1200L) // 6600 + 1200·1200/6600 = 6600 + 218 = 6818
  assert_eq(cc.window(), 6818L)
}

///|
test "congestion: the window never drops below the minimum of two datagrams" {
  let cc = NewReno::new(1200L)
  // 12000 → 6000 → 3000 → floored at 2·1200 = 2400 (ssthresh would be 1500).
  cc.on_congestion()
  cc.on_congestion()
  cc.on_congestion()
  assert_eq(cc.ssthresh(), 1500L)
  assert_eq(cc.window(), 2400L)
}

///|
test "congestion: can_send respects the window and bytes in flight" {
  let cc = NewReno::new(1200L) // window 12000
  assert_eq(cc.can_send(1200L), true)
  for _i = 0; _i < 10; _i = _i + 1 {
    cc.on_sent(1200L)
  }
  assert_eq(cc.in_flight(), 12000L)
  assert_eq(cc.can_send(1L), false) // window full
  assert_eq(cc.can_send(0L), true)
}
