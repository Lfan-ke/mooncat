// QUIC RTT estimation (RFC 9002 §5.3, §6.2.1), microseconds throughout.

///|
test "rtt: the first sample seeds smoothed_rtt and rttvar (RFC 9002 §5.3)" {
  let rtt = RttEstimator::new()
  rtt.update(100000L, 0L, 25000L)
  assert_eq(rtt.latest(), 100000L)
  assert_eq(rtt.min(), 100000L)
  assert_eq(rtt.smoothed(), 100000L)
  assert_eq(rtt.variation(), 50000L) // latest_rtt / 2
}

///|
test "rtt: later samples fold the EWMA and discount the ack delay (RFC 9002 §5.3)" {
  let rtt = RttEstimator::new()
  rtt.update(100000L, 0L, 25000L)
  // Second sample below min_rtt: no ack-delay subtraction (would drop below min_rtt).
  rtt.update(80000L, 5000L, 25000L)
  assert_eq(rtt.min(), 80000L)
  // rttvar = (3·50000 + |100000-80000|)/4 = 170000/4 = 42500
  assert_eq(rtt.variation(), 42500L)
  // smoothed = (7·100000 + 80000)/8 = 780000/8 = 97500
  assert_eq(rtt.smoothed(), 97500L)
  // Third sample above min_rtt + ack_delay: the ack delay is subtracted.
  rtt.update(120000L, 10000L, 25000L)
  assert_eq(rtt.min(), 80000L) // unchanged
  // adjusted = 120000 - 10000 = 110000
  // rttvar = (3·42500 + |97500-110000|)/4 = (127500+12500)/4 = 35000
  assert_eq(rtt.variation(), 35000L)
  // smoothed = (7·97500 + 110000)/8 = 792500/8 = 99062 (integer division)
  assert_eq(rtt.smoothed(), 99062L)
}

///|
test "rtt: the ack delay is capped at max_ack_delay (RFC 9002 §5.3)" {
  let rtt = RttEstimator::new()
  rtt.update(100000L, 0L, 25000L)
  // A reported ack_delay (40000) beyond max_ack_delay (25000) is capped to 25000.
  rtt.update(200000L, 40000L, 25000L)
  // adjusted = 200000 - 25000 = 175000 (capped delay), since 200000 >= 100000 + 25000
  // smoothed = (7·100000 + 175000)/8 = 875000/8 = 109375
  assert_eq(rtt.smoothed(), 109375L)
}

///|
test "rtt: the PTO is smoothed + max(4·rttvar, granularity) + max_ack_delay (RFC 9002 §6.2.1)" {
  let rtt = RttEstimator::new()
  rtt.update(100000L, 0L, 25000L)
  rtt.update(80000L, 5000L, 25000L)
  rtt.update(120000L, 10000L, 25000L)
  // smoothed=99062, rttvar=35000; 4·rttvar=140000 > granularity(1000).
  // pto = 99062 + 140000 + 25000 = 264062
  assert_eq(rtt.pto(25000L, 1000L), 264062L)
}
