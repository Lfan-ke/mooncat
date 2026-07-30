// QUIC packet-threshold loss detection (RFC 9002 §6.1.1).

///|
test "loss: an ACK drops acknowledged packets and advances largest_acked" {
  let t = SentPacketTracker::new()
  for pn = 0L; pn < 5L; pn = pn + 1L {
    t.on_sent(pn)
  }
  assert_eq(t.largest_acked(), -1L)
  // An ACK for packets 2 and 4: two newly acknowledged, the rest still outstanding.
  assert_eq(t.on_ack([2L, 4L]), 2)
  assert_eq(t.outstanding(), [0L, 1L, 3L])
  assert_eq(t.largest_acked(), 4L)
}

///|
test "loss: packets three or more before the largest acknowledged are declared lost" {
  let t = SentPacketTracker::new()
  for pn = 0L; pn < 5L; pn = pn + 1L {
    t.on_sent(pn)
  }
  let _ = t.on_ack([2L, 4L])
  // largest_acked = 4; threshold 3 → lost when 4 - pn >= 3, i.e. pn <= 1.
  assert_eq(t.detect_lost(3L), [0L, 1L])
  // 3 is only one before the largest acknowledged: still outstanding, not lost.
  assert_eq(t.outstanding(), [3L])
}

///|
test "loss: nothing is lost until the threshold gap opens" {
  let t = SentPacketTracker::new()
  t.on_sent(0L)
  t.on_sent(1L)
  t.on_sent(2L)
  let _ = t.on_ack([2L])
  // largest_acked = 2; 2 - 0 = 2 and 2 - 1 = 1, both below threshold 3.
  assert_eq(t.detect_lost(3L), [])
  assert_eq(t.outstanding(), [0L, 1L])
}

///|
test "loss: a real ACK frame's ranges acknowledge packets and drive loss detection" {
  let t = SentPacketTracker::new()
  for pn = 0L; pn < 10L; pn = pn + 1L {
    t.on_sent(pn)
  }
  // An ACK frame acknowledging [5,9] (first range) and [0,2] (one gap of one back): packets 3
  // and 4 are the hole.
  let ack : QuicFrame = Ack(largest=9UL, delay=0UL, first_range=4UL, ranges=[
    (1UL, 2UL),
  ])
  let ranges = quic_ack_frame_ranges(ack)
  assert_eq(ranges, [(0L, 2L), (5L, 9L)])
  assert_eq(t.on_ack_ranges(ranges), 8)
  assert_eq(t.outstanding(), [3L, 4L])
  assert_eq(t.largest_acked(), 9L)
  // Both 3 and 4 are more than three before the largest acknowledged (9): lost.
  assert_eq(t.detect_lost(3L), [3L, 4L])
}

///|
test "loss: nothing is declared lost before the first ACK" {
  let t = SentPacketTracker::new()
  t.on_sent(0L)
  t.on_sent(1L)
  assert_eq(t.detect_lost(3L), [])
  assert_eq(t.outstanding(), [0L, 1L])
}
