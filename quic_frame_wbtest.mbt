///|
test "CRYPTO frame encodes and parses per RFC 9000 §19.6" {
  // offset 1, data aabb -> type 06, offset 01, length 02, then the data.
  let f : QuicFrame = Crypto(offset=1UL, data=qv_hexb("aabb"))
  assert_eq(qv_hex(encode_frame(f)), "060102aabb")
  match parse_frame(qv_hexb("060102aabb")[:]) {
    Some((g, n)) => {
      assert_eq(g, f)
      assert_eq(n, 5)
    }
    None => fail("expected a CRYPTO frame")
  }
}

///|
test "PING and PADDING frames round-trip" {
  assert_eq(qv_hex(encode_frame(Ping)), "01")
  match parse_frame(qv_hexb("01")[:]) {
    Some((g, n)) => {
      assert_eq(g, Ping)
      assert_eq(n, 1)
    }
    None => fail("expected PING")
  }
  assert_eq(qv_hex(encode_frame(Padding(3))), "000000")
  // A run of zero bytes is one PADDING frame; it stops at the following PING byte.
  match parse_frame(qv_hexb("00000001")[:]) {
    Some((g, n)) => {
      assert_eq(g, Padding(3))
      assert_eq(n, 3)
    }
    None => fail("expected PADDING")
  }
}

///|
test "CRYPTO frame with a large offset uses a multi-byte varint" {
  let f : QuicFrame = Crypto(offset=15293UL, data=qv_hexb("00"))
  // offset 15293 encodes as the two-byte varint 7bbd.
  let enc = encode_frame(f)
  assert_eq(qv_hex(enc), "067bbd0100")
  match parse_frame(enc[:]) {
    Some((g, _)) => assert_eq(g, f)
    None => fail("expected CRYPTO")
  }
}

///|
test "a truncated CRYPTO frame parses to None" {
  // Declares 4 bytes of crypto data but supplies only 1.
  assert_eq(parse_frame(qv_hexb("060004aa")[:]) is None, true)
}
