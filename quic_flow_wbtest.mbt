// QUIC flow-control accounting (RFC 9000 §4): send-window consumption and blocking,
// receive-window enforcement, and the extend-when-half-consumed auto-tuning.

///|
test "send flow: available shrinks with sends and refuses to overshoot" {
  let f = SendFlow::new(100)
  assert_eq(f.available(), 100)
  assert_eq(f.is_blocked(), false)
  f.record_sent(30)
  assert_eq(f.sent(), 30)
  assert_eq(f.available(), 70)
  f.record_sent(70)
  assert_eq(f.available(), 0)
  assert_eq(f.is_blocked(), true)
  let overshoot = try {
    f.record_sent(1)
    false
  } catch {
    _ => true
  }
  assert_eq(overshoot, true)
}

///|
test "send flow: the limit only ever grows" {
  let f = SendFlow::new(100)
  f.record_sent(100)
  assert_eq(f.is_blocked(), true)
  f.update_limit(200)
  assert_eq(f.available(), 100)
  assert_eq(f.is_blocked(), false)
  // A stale, smaller MAX_DATA is ignored.
  f.update_limit(150)
  assert_eq(f.available(), 100)
}

///|
test "recv flow: data past the advertised limit is a violation" {
  let f = RecvFlow::new(100)
  assert_eq(f.limit(), 100)
  f.record_received(50) // within the window
  f.record_received(100) // exactly at the limit is allowed
  let violation = try {
    f.record_received(101)
    false
  } catch {
    _ => true
  }
  assert_eq(violation, true)
}

///|
test "recv flow: the window extends once half is consumed" {
  let f = RecvFlow::new(100)
  f.record_received(60)
  f.consume(40)
  // Consumed 40 of a 100-byte window: desired 140 is not yet half a window past 100.
  assert_eq(f.should_extend(), false)
  f.consume(20) // consumed 60 -> desired 160 >= 100 + 50
  assert_eq(f.should_extend(), true)
  assert_eq(f.extend_limit(), 160)
  assert_eq(f.limit(), 160)
  // Just extended: no further extension is due yet.
  assert_eq(f.should_extend(), false)
  // The peer may now send further, up to the new limit.
  f.record_received(160)
  let violation = try {
    f.record_received(161)
    false
  } catch {
    _ => true
  }
  assert_eq(violation, true)
}
