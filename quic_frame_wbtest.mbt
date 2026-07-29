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
test "MAX_DATA and HANDSHAKE_DONE frames round-trip (RFC 9000 §19.9 / §19.20)" {
  assert_eq(qv_hex(encode_frame(MaxData(15293UL))), "107bbd")
  match parse_frame(qv_hexb("107bbd")[:]) {
    Some((g, n)) => {
      assert_eq(g, MaxData(15293UL))
      assert_eq(n, 3)
    }
    None => fail("expected MAX_DATA")
  }
  assert_eq(qv_hex(encode_frame(HandshakeDone)), "1e")
  match parse_frame(qv_hexb("1e")[:]) {
    Some((g, n)) => {
      assert_eq(g, HandshakeDone)
      assert_eq(n, 1)
    }
    None => fail("expected HANDSHAKE_DONE")
  }
}

///|
test "CONNECTION_CLOSE transport and application variants (RFC 9000 §19.19)" {
  // Transport close (0x1c): error code, triggering frame type, reason.
  let t : QuicFrame = ConnectionClose(
    error_code=7UL,
    frame_type=Some(8UL),
    reason=qv_hexb("6279"),
  )
  assert_eq(qv_hex(encode_frame(t)), "1c0708026279")
  match parse_frame(qv_hexb("1c0708026279")[:]) {
    Some((g, _)) => assert_eq(g, t)
    None => fail("expected a transport CONNECTION_CLOSE")
  }
  // Application close (0x1d): error code, reason, no frame type.
  let a : QuicFrame = ConnectionClose(
    error_code=1UL,
    frame_type=None,
    reason=qv_hexb(""),
  )
  assert_eq(qv_hex(encode_frame(a)), "1d0100")
  match parse_frame(qv_hexb("1d0100")[:]) {
    Some((g, _)) => assert_eq(g, a)
    None => fail("expected an application CONNECTION_CLOSE")
  }
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

///|
test "RESET_STREAM and STOP_SENDING round-trip (RFC 9000 §19.4/§19.5)" {
  let rs : QuicFrame = ResetStream(id=4UL, error_code=0UL, final_size=100UL)
  // type 04, id 04, error 00, final_size 100 -> two-byte varint 4064.
  assert_eq(qv_hex(encode_frame(rs)), "0404004064")
  match parse_frame(qv_hexb("0404004064")[:]) {
    Some((g, n)) => {
      assert_eq(g, rs)
      assert_eq(n, 5)
    }
    None => fail("expected RESET_STREAM")
  }
  let ss : QuicFrame = StopSending(id=8UL, error_code=2UL)
  assert_eq(qv_hex(encode_frame(ss)), "050802")
  match parse_frame(qv_hexb("050802")[:]) {
    Some((g, _)) => assert_eq(g, ss)
    None => fail("expected STOP_SENDING")
  }
}

///|
test "flow-control frames round-trip (RFC 9000 §19.10-§19.14)" {
  let frames : Array[QuicFrame] = [
    MaxStreamData(id=4UL, max=1024UL),
    MaxStreams(bidi=true, max=5UL),
    MaxStreams(bidi=false, max=3UL),
    DataBlocked(2048UL),
    StreamDataBlocked(id=8UL, max=512UL),
    StreamsBlocked(bidi=true, max=1UL),
    StreamsBlocked(bidi=false, max=7UL),
  ]
  for f in frames {
    let enc = encode_frame(f)
    match parse_frame(enc[:]) {
      Some((g, n)) => {
        assert_eq(g, f)
        assert_eq(n, enc.length())
      }
      None => fail("flow-control frame should parse")
    }
  }
  // MAX_STREAMS bidi uses type 0x12, uni 0x13.
  assert_eq(qv_hex(encode_frame(MaxStreams(bidi=true, max=5UL))), "1205")
  assert_eq(qv_hex(encode_frame(MaxStreams(bidi=false, max=5UL))), "1305")
}

///|
test "connection-management and path frames round-trip (RFC 9000 §19.7/§19.15-§19.18)" {
  let nt : QuicFrame = NewToken(token=qv_hexb("aabbcc"))
  assert_eq(qv_hex(encode_frame(nt)), "0703aabbcc")
  match parse_frame(qv_hexb("0703aabbcc")[:]) {
    Some((g, _)) => assert_eq(g, nt)
    None => fail("expected NEW_TOKEN")
  }
  let nci : QuicFrame = NewConnectionId(
    seq=1UL,
    retire_prior_to=0UL,
    conn_id=qv_hexb("aabbccdd"),
    reset_token=qv_hexb("000102030405060708090a0b0c0d0e0f"),
  )
  assert_eq(
    qv_hex(encode_frame(nci)),
    "18010004aabbccdd000102030405060708090a0b0c0d0e0f",
  )
  match parse_frame(encode_frame(nci)[:]) {
    Some((g, _)) => assert_eq(g, nci)
    None => fail("expected NEW_CONNECTION_ID")
  }
  let rci : QuicFrame = RetireConnectionId(3UL)
  assert_eq(qv_hex(encode_frame(rci)), "1903")
  match parse_frame(qv_hexb("1903")[:]) {
    Some((g, _)) => assert_eq(g, rci)
    None => fail("expected RETIRE_CONNECTION_ID")
  }
  let pc : QuicFrame = PathChallenge(qv_hexb("0011223344556677"))
  assert_eq(qv_hex(encode_frame(pc)), "1a0011223344556677")
  match parse_frame(qv_hexb("1a0011223344556677")[:]) {
    Some((g, n)) => {
      assert_eq(g, pc)
      assert_eq(n, 9)
    }
    None => fail("expected PATH_CHALLENGE")
  }
  let pr : QuicFrame = PathResponse(qv_hexb("8899aabbccddeeff"))
  assert_eq(qv_hex(encode_frame(pr)), "1b8899aabbccddeeff")
  match parse_frame(qv_hexb("1b8899aabbccddeeff")[:]) {
    Some((g, _)) => assert_eq(g, pr)
    None => fail("expected PATH_RESPONSE")
  }
}

///|
test "a truncated PATH_CHALLENGE parses to None" {
  // Declares the frame but supplies only 4 of the 8 data bytes.
  assert_eq(parse_frame(qv_hexb("1a00112233")[:]) is None, true)
}
