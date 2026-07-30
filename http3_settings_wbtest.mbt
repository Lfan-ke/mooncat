// HTTP/3 SETTINGS on the control stream (RFC 9114 §6.2.1, §7.2.4).

///|
test "http3 settings: the named settings map to their RFC 9114 identifiers" {
  let s = Http3Settings::new(4096UL, 16384UL, 100UL)
  assert_eq(s.to_pairs(), [(0x01UL, 4096UL), (0x06UL, 16384UL), (0x07UL, 100UL)])
}

///|
test "http3 settings: an endpoint's settings round-trip through its control stream" {
  let s = Http3Settings::new(4096UL, 16384UL, 100UL)
  let ctrl = http3_encode_control_stream(s.to_pairs())
  // The control stream opens with the control-stream type 0x00.
  assert_eq(ctrl[0], b'\x00')
  let back = match http3_decode_control_stream(ctrl[:]) {
    Some(v) => v
    None => abort("expected a control stream with SETTINGS")
  }
  assert_eq(back.qpack_max_table_capacity, 4096UL)
  assert_eq(back.max_field_section_size, 16384UL)
  assert_eq(back.qpack_blocked_streams, 100UL)
}

///|
test "http3 settings: unknown settings are ignored and absent ones default to zero" {
  // A peer sends a known setting plus a greased/unknown identifier; the unknown is dropped and
  // the absent QPACK settings default to zero.
  let s = Http3Settings::from_pairs([(0x06UL, 8192UL), (0x1fUL, 999UL)])
  assert_eq(s.max_field_section_size, 8192UL)
  assert_eq(s.qpack_max_table_capacity, 0UL)
  assert_eq(s.qpack_blocked_streams, 0UL)
}
