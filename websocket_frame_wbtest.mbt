// The WebSocket frame layer (RFC 6455 §5.2) — byte-exact against the §5.7 examples.

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
  guard ws_decode_frame(out[:]) is Some((frame, consumed)) else {
    abort("expected a 16-bit-length frame")
  }
  assert_eq(frame.payload.length(), 200)
  assert_eq(consumed, 204)
  // 70000 bytes → the 127 marker and a 64-bit length.
  let big = Bytes::make(70000, b'B')
  let out2 = ws_encode_frame(true, Binary, big)
  assert_eq(out2[0], b'\x82')
  assert_eq(out2[1], b'\x7f')
  guard ws_decode_frame(out2[:]) is Some((f2, _)) else {
    abort("expected a 64-bit-length frame")
  }
  assert_eq(f2.payload.length(), 70000)
}

///|
async test "ws_read_frame reads consecutive frames off a raw stream" {
  @async.with_task_group(_g => {
    // A masked client text "Hello" followed by an unmasked ping "hi", back to back.
    let masked = ws_encode_frame(true, Text, b"Hello", mask=b"\x37\xfa\x21\x3d")
    let ping = ws_encode_frame(true, Ping, b"hi")
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
  // A reserved opcode (0x3) is rejected.
  assert_eq(ws_decode_frame(b"\x83\x00"[:]), None)
}
