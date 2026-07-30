// QUIC loss detection (RFC 9002 §6.1): packet threshold (§6.1.1) and time threshold (§6.1.2).

///|
test "loss: an ACK drops acknowledged packets, sums their bytes, and advances largest_acked" {
  let t = SentPacketTracker::new()
  for pn = 0L; pn < 5L; pn = pn + 1L {
    t.on_sent(pn, pn * 1000L, 1200L)
  }
  assert_eq(t.largest_acked(), -1L)
  // An ACK for packets 2 and 4: 2 × 1200 bytes newly acknowledged, the rest still outstanding.
  assert_eq(t.on_ack([2L, 4L]), 2400L)
  assert_eq(t.outstanding(), [0L, 1L, 3L])
  assert_eq(t.largest_acked(), 4L)
}

///|
test "loss: packets three or more before the largest acknowledged are declared lost (§6.1.1)" {
  let t = SentPacketTracker::new()
  for pn = 0L; pn < 5L; pn = pn + 1L {
    t.on_sent(pn, 0L, 1200L)
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
  t.on_sent(0L, 0L, 1200L)
  t.on_sent(1L, 0L, 1200L)
  t.on_sent(2L, 0L, 1200L)
  let _ = t.on_ack([2L])
  // largest_acked = 2; 2 - 0 = 2 and 2 - 1 = 1, both below threshold 3.
  assert_eq(t.detect_lost(3L), [])
  assert_eq(t.outstanding(), [0L, 1L])
}

///|
test "loss: a real ACK frame's ranges acknowledge packets and drive loss detection" {
  let t = SentPacketTracker::new()
  for pn = 0L; pn < 10L; pn = pn + 1L {
    t.on_sent(pn, 0L, 1200L)
  }
  // An ACK frame acknowledging [5,9] (first range) and [0,2] (one gap back): 3 and 4 are the hole.
  let ack : QuicFrame = Ack(largest=9UL, delay=0UL, first_range=4UL, ranges=[
    (1UL, 2UL),
  ])
  let ranges = quic_ack_frame_ranges(ack)
  assert_eq(ranges, [(0L, 2L), (5L, 9L)])
  // Eight packets acknowledged × 1200 bytes.
  assert_eq(t.on_ack_ranges(ranges), 9600L)
  assert_eq(t.outstanding(), [3L, 4L])
  assert_eq(t.largest_acked(), 9L)
  assert_eq(t.detect_lost(3L), [3L, 4L])
}

///|
test "loss: packets older than the time threshold are declared lost (§6.1.2)" {
  let t = SentPacketTracker::new()
  // Five packets a millisecond apart (microseconds).
  for pn = 0L; pn < 5L; pn = pn + 1L {
    t.on_sent(pn, pn * 1000L, 1200L)
  }
  let _ = t.on_ack([4L]) // largest_acked = 4, sent at t=4000
  // At now = 4000 with a 1500 µs threshold, packets sent at or before t=2500 are lost:
  // pn 0,1,2 (t 0,1000,2000); pn 3 (t 3000) is too recent.
  assert_eq(t.detect_lost_time(4000L, 1500L), [0L, 1L, 2L])
  assert_eq(t.outstanding(), [3L])
}

///|
test "loss: the time threshold is 9/8 · max(smoothed, latest) floored at the granularity (§6.1.2)" {
  let rtt = RttEstimator::new()
  rtt.update(100000L, 0L, 25000L) // smoothed = latest = 100000
  // 9/8 · 100000 = 112500 > granularity 1000.
  assert_eq(quic_loss_time_threshold(rtt, 1000L), 112500L)
  // A tiny RTT floors at the granularity.
  let small = RttEstimator::new()
  small.update(400L, 0L, 25000L) // 9/8 · 400 = 450 < 1000
  assert_eq(quic_loss_time_threshold(small, 1000L), 1000L)
}
