// The WebSocket frame layer (RFC 6455 §5.2) — byte-exact against the §5.7 examples, and the
// receive rules of §5.1/§5.2/§5.5 that decide which close code a bad frame is failed with.

///|
test "ws frame: unmasked text 'Hello' matches RFC 6455 §5.7" {
  assert_eq(
    ws_encode_frame(true, Text, b"Hello"),
    b"\x81\x05\x48\x65\x6c\x6c\x6f",
  )
}

///|
test "ws frame: masked text 'Hello' matches RFC 6455 §5.7" {
  let out = ws_encode_frame(true, Text, b"Hello", mask=b"\x37\xfa\x21\x3d")
  assert_eq(out, b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58")
}

///|
test "ws frame: decode unmasks a client frame back to its payload" {
  let framed : Bytes = b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58"
  guard ws_decode_frame(framed[:]) is Some((frame, consumed)) else {
    abort("expected a complete frame")
  }
  assert_eq(frame.fin, true)
  assert_eq(frame.opcode, Text)
  assert_eq(frame.payload, b"Hello")
  assert_eq(consumed, 11)
}

///|
test "ws frame: control opcodes ping/pong/close encode per §5.5" {
  assert_eq(
    ws_encode_frame(true, Ping, b"Hello"),
    b"\x89\x05\x48\x65\x6c\x6c\x6f",
  )
  assert_eq(ws_encode_frame(true, Pong, b""), b"\x8a\x00")
  // Close carrying the 2-byte status code 1000 (0x03e8).
  assert_eq(ws_encode_frame(true, Close, b"\x03\xe8"), b"\x88\x02\x03\xe8")
}

///|
test "ws frame: 16-bit and 64-bit length forms round-trip" {
  // 200 bytes → the 126 marker plus a 16-bit length (0x00c8).
  let p200 = Bytes::make(200, b'A')
  let out = ws_encode_frame(true, Binary, p200)
  assert_eq(out[0], b'\x82')
  assert_eq(out[1], b'\x7e')
  assert_eq(out[2], b'\x00')
  assert_eq(out[3], b'\xc8')
  // Server → client frames are unmasked, so the client's receive rules apply, not the server's.
  guard ws_decode_frame(out[:], from_client=false) is Some((frame, consumed)) else {
    abort("expected a 16-bit-length frame")
  }
  assert_eq(frame.payload.length(), 200)
  assert_eq(consumed, 204)
  // 70000 bytes → the 127 marker and a 64-bit length.
  let big = Bytes::make(70000, b'B')
  let out2 = ws_encode_frame(true, Binary, big)
  assert_eq(out2[0], b'\x82')
  assert_eq(out2[1], b'\x7f')
  guard ws_decode_frame(out2[:], from_client=false) is Some((f2, _)) else {
    abort("expected a 64-bit-length frame")
  }
  assert_eq(f2.payload.length(), 70000)
}

///|
async test "ws_read_frame reads consecutive frames off a raw stream" {
  @async.with_task_group(_g => {
    // Two masked client frames back to back: a text "Hello" and a ping.
    let masked = ws_encode_frame(true, Text, b"Hello", mask=b"\x37\xfa\x21\x3d")
    let ping = ws_encode_frame(true, Ping, b"hi", mask=b"\x01\x02\x03\x04")
    let reader : &@io.Reader = @io.MemoryReader(async fn(w) {
      w.write(masked)
      w.write(ping)
    })
    let f1 = ws_read_frame(reader)
    assert_eq(f1.opcode, Text)
    assert_eq(f1.fin, true)
    assert_eq(f1.payload, b"Hello")
    let f2 = ws_read_frame(reader)
    assert_eq(f2.opcode, Ping)
    assert_eq(f2.payload, b"hi")
  })
}

///|
test "ws frame: an incomplete frame decodes to None" {
  // A masked header claiming 5 payload bytes but only 2 present.
  assert_eq(ws_decode_frame(b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f"[:]), None)
}

///|
/// The close code `ws_decode_frame` fails `frame` with, or `0` when it accepts it. A violation and
/// a short buffer are different answers — `None` means "not yet", a raise means "never".
fn ws_reject_code(
  frame : Bytes,
  from_client? : Bool = true,
  max_size? : Int = ws_max_size,
) -> Int {
  try {
    ignore(ws_decode_frame(frame[:], from_client~, max_size~))
    0
  } catch {
    WsError(code, _) => code
  }
}

///|
/// §5.2: RSV1, RSV2 and RSV3 must be clear when no extension has been negotiated, and mooncat
/// negotiates none. A peer that sets one is asking for a framing this endpoint does not implement,
/// so the connection is failed rather than the bit ignored.
test "ws receive: a set RSV bit fails the connection with 1002 (§5.2)" {
  // 0xC1 = FIN + RSV1 + text; 0x81 alone would be accepted.
  assert_eq(ws_reject_code(b"\xc1\x80\x00\x00\x00\x00"), 1002)
  // RSV2 (0xA1) and RSV3 (0x91) likewise.
  assert_eq(ws_reject_code(b"\xa1\x80\x00\x00\x00\x00"), 1002)
  assert_eq(ws_reject_code(b"\x91\x80\x00\x00\x00\x00"), 1002)
  // The same frame with all three clear is accepted.
  assert_eq(ws_reject_code(b"\x81\x80\x00\x00\x00\x00"), 0)
}

///|
/// §5.2: opcodes 0x3–0x7 and 0xB–0xF are reserved. A reserved opcode is a violation, not a short
/// read, so it raises rather than reporting an incomplete buffer.
test "ws receive: a reserved opcode fails the connection with 1002 (§5.2)" {
  assert_eq(ws_reject_code(b"\x83\x80\x00\x00\x00\x00"), 1002)
  assert_eq(ws_reject_code(b"\x8b\x80\x00\x00\x00\x00"), 1002)
}

///|
/// §5.1: every frame a client sends must be masked. An unmasked client frame is the shape a
/// hand-rolled attack tool sends, and accepting it also means accepting the cache-poisoning
/// exposure masking exists to prevent.
test "ws receive: an unmasked client frame fails the connection with 1002 (§5.1)" {
  // FIN + text, MASK clear, one payload byte.
  assert_eq(ws_reject_code(b"\x81\x01\x41"), 1002)
  // The same bytes read as a server → client frame are perfectly legal.
  assert_eq(ws_reject_code(b"\x81\x01\x41", from_client=false), 0)
}

///|
/// §5.5: a control frame carries at most 125 bytes and is never fragmented. Both rules exist so a
/// control frame can be handled without buffering, which is the point of a control frame.
test "ws receive: an oversized or fragmented control frame fails with 1002 (§5.5)" {
  // A close (0x88) announcing 126 bytes via the 16-bit form.
  assert_eq(ws_reject_code(b"\x88\xfe\x00\x7e\x00\x00\x00\x00"), 1002)
  // A ping with FIN clear (0x09 rather than 0x89) is a fragmented control frame.
  assert_eq(ws_reject_code(b"\x09\x80\x00\x00\x00\x00"), 1002)
  // 125 bytes with FIN set is the largest legal control frame.
  assert_eq(ws_reject_code(b"\x88\xfd\x00\x00\x00\x00"), 0)
}

///|
/// §5.2: the 64-bit length is a full unsigned quantity, so it must be checked before it is narrowed
/// to the machine word a buffer length is. `0x0000_0001_0000_0001` truncates to `1` in 32 bits —
/// a peer announcing 4 GiB would otherwise be read as a one-byte frame and the stream would
/// desynchronise from there.
test "ws receive: a 64-bit length past the ceiling fails with 1009 (§5.2)" {
  assert_eq(ws_reject_code(b"\x82\xff\x00\x00\x00\x01\x00\x00\x00\x01"), 1009)
  // The reserved sign bit set: 0xFFFF... is not a length any endpoint can honour.
  assert_eq(ws_reject_code(b"\x82\xff\xff\xff\xff\xff\xff\xff\xff\xff"), 1009)
  // A 16-bit length past a small configured ceiling is refused the same way.
  assert_eq(
    ws_reject_code(b"\x82\xfe\x01\x00\x00\x00\x00\x00", max_size=16),
    1009,
  )
  // ...and one within it is not.
  assert_eq(ws_reject_code(b"\x82\x8a\x00\x00\x00\x00", max_size=16), 0)
}

///|
/// The rules apply in the order §5.2 states them, so a frame breaking several is reported by the
/// first: an RSV bit outranks a bad length, since an extension might have defined that length.
test "ws receive: ws_check_frame reports the first rule broken" {
  let code = try {
    ignore(
      ws_check_frame(0xC2, 0xFF, 1L << 40, from_client=true, max_size=1024),
    )
    0
  } catch {
    WsError(c, _) => c
  }
  assert_eq(code, 1002)
}
