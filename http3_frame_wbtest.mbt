// HTTP/3 frame codec vectors (RFC 9114 §7.2), constructed byte-for-byte from the frame
// format — a type varint, a length varint, then the payload. The encoder's output is
// checked exactly, and each frame decodes back to its typed form; reserved/grease and
// HTTP/2-reused types, partial reads, and malformed SETTINGS are all covered.

///|
test "http3 frame encode: DATA, HEADERS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID" {
  assert_eq(http3_frame_encode(Data(b"\x68\x69")), b"\x00\x02\x68\x69")
  assert_eq(http3_frame_encode(Headers(b"\xab\xcd")), b"\x01\x02\xab\xcd")
  assert_eq(http3_frame_encode(GoAway(0)), b"\x07\x01\x00")
  assert_eq(http3_frame_encode(CancelPush(5)), b"\x03\x01\x05")
  assert_eq(http3_frame_encode(MaxPushId(5)), b"\x0d\x01\x05")
}

///|
test "http3 frame encode: SETTINGS pairs and PUSH_PROMISE" {
  // SETTINGS with two 1-byte-varint pairs: (0x06, 0x00), (0x01, 0x00).
  assert_eq(
    http3_frame_encode(Settings([(0x06, 0x00), (0x01, 0x00)])),
    b"\x04\x04\x06\x00\x01\x00",
  )
  // PUSH_PROMISE: push id 3 then the field block.
  assert_eq(
    http3_frame_encode(PushPromise(3, b"\xff\xee")),
    b"\x05\x03\x03\xff\xee",
  )
}

///|
test "http3 frame decode: each frame round-trips to its typed form" {
  let cases : Array[Http3Frame] = [
    Data(b"\x68\x69"),
    Headers(b"\xab\xcd"),
    GoAway(0),
    CancelPush(5),
    MaxPushId(5),
    Settings([(0x06, 0x00), (0x01, 0x00)]),
    PushPromise(3, b"\xff\xee"),
  ]
  for frame in cases {
    let encoded = http3_frame_encode(frame)
    match http3_frame_decode(encoded[:]) {
      Some((decoded, consumed)) => {
        assert_eq(decoded, frame)
        assert_eq(consumed, encoded.length())
      }
      None => abort("expected a complete frame")
    }
  }
}

///|
test "http3 frame decode: multi-byte varint settings values round-trip" {
  // Values that need 2- and 4-byte QUIC varints exercise the length fields.
  let frame = Settings([(0x01, 4096), (0x06, 16384)])
  let encoded = http3_frame_encode(frame)
  match http3_frame_decode(encoded[:]) {
    Some((decoded, _)) => assert_eq(decoded, frame)
    None => abort("expected a complete frame")
  }
}

///|
test "http3 frame decode: reserved HTTP/2 types and grease types" {
  // 0x06 (HTTP/2 PING) is reused with no HTTP/3 meaning -> a connection error signal.
  match http3_frame_decode(b"\x06\x00"[:]) {
    Some((decoded, consumed)) => {
      assert_eq(decoded, ReservedHttp2(0x06))
      assert_eq(consumed, 2)
    }
    None => abort("expected a complete frame")
  }
  // An unknown/grease type is preserved as Reserved for the receiver to ignore.
  match http3_frame_decode(b"\x21\x01\x00"[:]) {
    Some((decoded, _)) => assert_eq(decoded, Reserved(0x21, b"\x00"))
    None => abort("expected a complete frame")
  }
}

///|
test "http3 frame decode: an incomplete frame yields None" {
  // Length says 4 payload octets but only 2 are present.
  assert_eq(http3_frame_decode(b"\x00\x04\x68\x69"[:]), None)
  // The length varint itself has not arrived.
  assert_eq(http3_frame_decode(b"\x00"[:]), None)
  // Empty input.
  assert_eq(http3_frame_decode(b""[:]), None)
}

///|
test "http3 frame decode_all: consumes whole frames, leaves a partial tail" {
  // Two complete frames followed by the start of a third.
  let stream = b"\x00\x02\x68\x69\x07\x01\x00\x00\x04\x68"
  let (frames, consumed) = http3_frame_decode_all(stream)
  assert_eq(frames.length(), 2)
  assert_eq(frames[0], Data(b"\x68\x69"))
  assert_eq(frames[1], GoAway(0))
  // The trailing partial DATA frame (needs 4 payload octets, has 1) is left unconsumed.
  assert_eq(consumed, 7)
}

///|
test "http3 frame decode: a truncated SETTINGS pair raises" {
  // SETTINGS length 3: identifier 0x06, value 0x00, then a dangling identifier 0x01.
  let bad = try {
    let _ = http3_frame_decode(b"\x04\x03\x06\x00\x01"[:])
    false
  } catch {
    _ => true
  }
  assert_eq(bad, true)
}
