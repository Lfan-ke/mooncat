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

///|
test "STREAM frame round-trips with offset, length, and FIN (RFC 9000 §19.8)" {
  // type 0e (OFF + LEN), stream 4, offset 0, length 5, data "hello".
  let f : QuicFrame = Stream(
    id=4UL,
    offset=0UL,
    fin=false,
    data=qv_hexb("68656c6c6f"),
  )
  assert_eq(qv_hex(encode_frame(f)), "0e04000568656c6c6f")
  match parse_frame(qv_hexb("0e04000568656c6c6f")[:]) {
    Some((g, n)) => {
      assert_eq(g, f)
      assert_eq(n, 9)
    }
    None => fail("expected a STREAM frame")
  }
  // FIN rides the low bit of the type (0f).
  let ff : QuicFrame = Stream(id=4UL, offset=10UL, fin=true, data=qv_hexb("78"))
  assert_eq(qv_hex(encode_frame(ff)), "0f040a0178")
  match parse_frame(qv_hexb("0f040a0178")[:]) {
    Some((g, _)) => assert_eq(g, ff)
    None => fail("expected a STREAM frame with FIN")
  }
}

///|
test "ACK frame encodes and parses per RFC 9000 §19.3" {
  // largest 10, delay 0, no additional ranges, first range 3.
  let f : QuicFrame = Ack(largest=10UL, delay=0UL, first_range=3UL, ranges=[])
  assert_eq(qv_hex(encode_frame(f)), "020a000003")
  match parse_frame(qv_hexb("020a000003")[:]) {
    Some((g, n)) => {
      assert_eq(g, f)
      assert_eq(n, 5)
    }
    None => fail("expected an ACK frame")
  }
  // With one extra range: gap 1, range length 3.
  let f2 : QuicFrame = Ack(largest=10UL, delay=0UL, first_range=2UL, ranges=[
    (1UL, 3UL),
  ])
  assert_eq(qv_hex(encode_frame(f2)), "020a0001020103")
  match parse_frame(qv_hexb("020a0001020103")[:]) {
    Some((g, n)) => {
      assert_eq(g, f2)
      assert_eq(n, 7)
    }
    None => fail("expected an ACK frame with a range")
  }
}

///|
test "a truncated ACK frame parses to None" {
  // Declares one range but supplies no gap/length pair.
  assert_eq(parse_frame(qv_hexb("020a000102")[:]) is None, true)
}

///|
test "a STREAM frame with no length field runs to the end of the buffer" {
  // type 0c = OFF set, LEN clear: stream id, offset, then data to the end.
  match parse_frame(qv_hexb("0c0400aabb")[:]) {
    Some((g, n)) => {
      assert_eq(g, Stream(id=4UL, offset=0UL, fin=false, data=qv_hexb("aabb")))
      assert_eq(n, 5)
    }
    None => fail("expected a length-less STREAM frame")
  }
}
