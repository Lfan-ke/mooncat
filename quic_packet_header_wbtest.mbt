///|
test "parse the RFC 9001 A.1 sample client Initial long header" {
  // The header prefix of RFC 9001 Appendix A.1's sample client Initial packet:
  // first byte c3 (Initial, packet-number length 4), version 1, an 8-byte DCID,
  // and an empty SCID.
  let bytes = qv_hexb("c300000001088394c8f03e51570800")
  match parse_long_header(bytes[:]) {
    Some((h, consumed)) => {
      assert_eq(h.packet_type, Initial)
      assert_eq(h.type_specific, 3)
      assert_eq(h.version, 1)
      assert_eq(qv_hex(h.dcid), "8394c8f03e515708")
      assert_eq(qv_hex(h.scid), "")
      assert_eq(consumed, 15)
    }
    None => fail("expected a valid long header")
  }
}

///|
test "long header round-trips for every packet type" {
  let types = [Initial, ZeroRtt, Handshake, Retry]
  for t in types {
    let h : QuicLongHeader = {
      packet_type: t,
      type_specific: 2,
      version: 1,
      dcid: qv_hexb("0102030405"),
      scid: qv_hexb("aabb"),
    }
    let encoded = encode_long_header(h)
    match parse_long_header(encoded[:]) {
      Some((decoded, consumed)) => {
        assert_eq(decoded, h)
        assert_eq(consumed, encoded.length())
      }
      None => fail("round-trip failed for a long header")
    }
  }
}

///|
test "a short header (high bit clear) and a truncated header are rejected" {
  // A short-header first byte (0x40) is not a long header.
  assert_eq(parse_long_header(qv_hexb("40000000")[:]) is None, true)
  // A DCID length that overruns the buffer decodes to None.
  assert_eq(parse_long_header(qv_hexb("c3000000010899")[:]) is None, true)
}
