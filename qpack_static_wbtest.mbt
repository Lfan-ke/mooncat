// QPACK static-table checks against RFC 9204 Appendix A: the table has exactly 99
// entries, spot-checked known indices match the RFC, and the exact-/name-lookup helpers
// return the indices an encoder would reference.

///|
test "qpack static: the table has exactly 99 entries" {
  assert_eq(qpack_static_len(), 99)
}

///|
test "qpack static: spot-checked entries match RFC 9204 Appendix A" {
  assert_eq(qpack_static_get(0), Some((":authority", "")))
  assert_eq(qpack_static_get(1), Some((":path", "/")))
  assert_eq(qpack_static_get(17), Some((":method", "GET")))
  assert_eq(qpack_static_get(25), Some((":status", "200")))
  assert_eq(
    qpack_static_get(31),
    Some(("accept-encoding", "gzip, deflate, br")),
  )
  assert_eq(qpack_static_get(46), Some(("content-type", "application/json")))
  assert_eq(qpack_static_get(98), Some(("x-frame-options", "sameorigin")))
  // Out of range.
  assert_eq(qpack_static_get(99), None)
  assert_eq(qpack_static_get(-1), None)
}

///|
test "qpack static: exact (name, value) lookup returns the RFC index" {
  assert_eq(qpack_static_find(":method", "GET"), Some(17))
  assert_eq(qpack_static_find(":status", "404"), Some(27))
  assert_eq(qpack_static_find("content-type", "text/plain"), Some(53))
  // A name that exists but not with this value.
  assert_eq(qpack_static_find(":status", "418"), None)
  // A name absent from the table.
  assert_eq(qpack_static_find("x-custom", "v"), None)
}

///|
test "qpack static: name-only lookup returns the first matching index" {
  // :method first appears at index 15 (CONNECT).
  assert_eq(qpack_static_find_name(":method"), Some(15))
  // :status first appears at index 24 (103).
  assert_eq(qpack_static_find_name(":status"), Some(24))
  assert_eq(qpack_static_find_name("cookie"), Some(5))
  assert_eq(qpack_static_find_name("x-custom"), None)
}
