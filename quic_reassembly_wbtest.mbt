// QUIC stream reassembly behaviour (RFC 9000 §2.2): fragments arriving in order, out of
// order, with gaps, overlapping (identically or in conflict), duplicated, or straddling
// the read cursor, plus final-size tracking from the fin bit.

///|
test "reassembly: in-order fragments read straight through" {
  let r = StreamReassembler::new()
  r.insert(0, b"abc", false)
  assert_eq(r.read(), b"abc")
  assert_eq(r.consumed(), 3)
  r.insert(3, b"def", false)
  assert_eq(r.read(), b"abcdef"[3:6].to_owned())
  assert_eq(r.consumed(), 6)
}

///|
test "reassembly: out-of-order fragments reorder before reading" {
  let r = StreamReassembler::new()
  r.insert(3, b"def", false)
  // Nothing contiguous yet — the run at offset 0 has not arrived.
  assert_eq(r.read(), b"")
  r.insert(0, b"abc", false)
  assert_eq(r.read(), b"abcdef")
}

///|
test "reassembly: a gap holds back later data until it is filled" {
  let r = StreamReassembler::new()
  r.insert(0, b"ab", false)
  r.insert(5, b"fg", false)
  assert_eq(r.read(), b"ab") // 2..4 still missing
  r.insert(2, b"cde", false)
  assert_eq(r.read(), b"cdefg")
  assert_eq(r.consumed(), 7)
}

///|
test "reassembly: identical overlap is merged, tail appended once" {
  let r = StreamReassembler::new()
  r.insert(0, b"abcd", false)
  r.insert(2, b"cdef", false) // overlaps cd, extends with ef
  assert_eq(r.read(), b"abcdef")
}

///|
test "reassembly: a duplicate fragment is idempotent" {
  let r = StreamReassembler::new()
  r.insert(0, b"abc", false)
  r.insert(0, b"abc", false)
  assert_eq(r.read(), b"abc")
  assert_eq(r.consumed(), 3)
}

///|
test "reassembly: a fragment straddling the read cursor keeps only its new tail" {
  let r = StreamReassembler::new()
  r.insert(0, b"abcdef", false)
  assert_eq(r.read(), b"abcdef")
  // Retransmit overlapping already-consumed bytes plus two new ones.
  r.insert(4, b"efgh", false)
  assert_eq(r.read(), b"gh")
  assert_eq(r.consumed(), 8)
}

///|
test "reassembly: fin sets the final size and completes when drained" {
  let r = StreamReassembler::new()
  assert_eq(r.is_complete(), false)
  r.insert(0, b"abc", true)
  assert_eq(r.final_size(), Some(3))
  assert_eq(r.is_complete(), false) // not yet read
  assert_eq(r.read(), b"abc")
  assert_eq(r.is_complete(), true)
}

///|
test "reassembly: conflicting overlap bytes raise" {
  let r = StreamReassembler::new()
  r.insert(0, b"abcd", false)
  let conflict = try {
    r.insert(2, b"XYef", false) // bytes at 2..4 disagree (cd vs XY)
    false
  } catch {
    _ => true
  }
  assert_eq(conflict, true)
}

///|
test "reassembly: data beyond a known final size raises" {
  let r = StreamReassembler::new()
  r.insert(0, b"abc", true) // final size 3
  let beyond = try {
    r.insert(3, b"d", false)
    false
  } catch {
    _ => true
  }
  assert_eq(beyond, true)
}

///|
test "reassembly: two fins with different sizes raise" {
  let r = StreamReassembler::new()
  r.insert(0, b"abc", true)
  let conflict = try {
    r.insert(0, b"abcd", true) // final size 4 contradicts 3
    false
  } catch {
    _ => true
  }
  assert_eq(conflict, true)
}
