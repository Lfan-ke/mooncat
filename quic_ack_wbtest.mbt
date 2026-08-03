// QUIC ACK generation (RFC 9000 §19.3): building the Largest / First Range / (Gap,
// Length) fields from a received-packet set, the inverse reconstruction, and a
// round-trip through the ACK frame codec.

///|
test "ack: fields for a set with two gaps match RFC 9000 §19.3" {
  let set = AckRangeSet::new()
  for pn in [0, 1, 2, 4, 5, 7] {
    set.add(pn.to_uint64())
  }
  assert_eq(set.largest(), Some(7))
  assert_eq(set.contains(3), false)
  assert_eq(set.contains(5), true)
  // Largest 7, First Range 0 (only 7 in the top range), then two (Gap, Length) pairs.
  match set.to_ack_fields() {
    Some((largest, first_range, pairs)) => {
      assert_eq(largest, 7)
      assert_eq(first_range, 0)
      assert_eq(pairs, [(0, 1), (0, 2)])
    }
    None => abort("expected ack fields")
  }
}

///|
test "ack: to_ack_fields and ack_fields_to_ranges round-trip" {
  let set = AckRangeSet::new()
  for pn in [0, 1, 2, 4, 5, 7] {
    set.add(pn.to_uint64())
  }
  guard set.to_ack_fields() is Some((largest, first_range, pairs)) else {
    fail("to_ack_fields should be Some for this ack set")
  }
  assert_eq(ack_fields_to_ranges(largest, first_range, pairs), [
    (0, 2),
    (4, 5),
    (7, 7),
  ])
}

///|
test "ack: fields survive the ACK frame codec (encode then parse)" {
  let set = AckRangeSet::new()
  for pn in [10, 11, 12, 20] {
    set.add(pn.to_uint64())
  }
  guard set.to_ack_fields() is Some((largest, first_range, pairs)) else {
    fail("to_ack_fields should be Some for this ack set")
  }
  let frame : QuicFrame = Ack(largest~, delay=42, first_range~, ranges=pairs)
  match parse_frame(encode_frame(frame)[:]) {
    Some((decoded, _)) => assert_eq(decoded, frame)
    None => abort("expected a parsable ACK frame")
  }
  // And the reconstructed ranges match what went in.
  assert_eq(ack_fields_to_ranges(largest, first_range, pairs), [
    (10, 12),
    (20, 20),
  ])
}

///|
test "ack: a single packet and a contiguous run" {
  let one = AckRangeSet::new()
  one.add(5)
  match one.to_ack_fields() {
    Some((largest, first_range, pairs)) => {
      assert_eq(largest, 5)
      assert_eq(first_range, 0)
      assert_eq(pairs, [])
    }
    None => abort("expected ack fields")
  }
  let run = AckRangeSet::new()
  for pn in [3, 4, 5, 6] {
    run.add(pn.to_uint64())
  }
  guard run.to_ack_fields() is Some((largest, first_range, pairs)) else {
    fail("to_ack_fields should be Some for this ack set")
  }
  assert_eq((largest, first_range), (6, 3))
  assert_eq(pairs, [])
}

///|
test "ack: out-of-order and duplicate additions coalesce" {
  let set = AckRangeSet::new()
  for pn in [7, 3, 5, 4, 3, 6] {
    // 3..7 with a duplicate 3, arriving out of order
    set.add(pn.to_uint64())
  }
  guard set.to_ack_fields() is Some((largest, first_range, pairs)) else {
    fail("to_ack_fields should be Some for this ack set")
  }
  assert_eq((largest, first_range), (7, 4)) // 3..7 is one range
  assert_eq(pairs, [])
}

///|
test "ack: empty set has no fields" {
  let set = AckRangeSet::new()
  assert_eq(set.is_empty(), true)
  assert_eq(set.largest(), None)
  assert_eq(set.to_ack_fields(), None)
}

///|
test "ack: a gap that underflows the packet-number space is rejected" {
  // Largest 3, first range 0 -> smallest 3; a Gap of 5 would put the next range below 0.
  let bad = try {
    let _ = ack_fields_to_ranges(3, 0, [(5, 0)])
    false
  } catch {
    _ => true
  }
  assert_eq(bad, true)
}
