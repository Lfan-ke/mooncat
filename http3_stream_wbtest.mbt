// HTTP/3 unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2).

///|
/// Encode a stream's opening bytes and decode them back.
fn roundtrip_stream(s : Http3UniStream) -> Http3UniStream raise {
  let wire = http3_encode_stream_type(s)
  match http3_decode_stream_type(wire[:]) {
    Some((got, consumed)) => {
      assert_eq(consumed, wire.length())
      got
    }
    None => abort("incomplete stream type")
  }
}

///|
test "http3 stream: every unidirectional type round-trips" {
  assert_eq(roundtrip_stream(ControlStream), ControlStream)
  assert_eq(roundtrip_stream(PushStream(42)), PushStream(42))
  assert_eq(roundtrip_stream(QpackEncoderStream), QpackEncoderStream)
  assert_eq(roundtrip_stream(QpackDecoderStream), QpackDecoderStream)
  // A greased/reserved type (0x21 = 0x1f*1 + 2) and a large one.
  assert_eq(roundtrip_stream(ReservedStream(0x21)), ReservedStream(0x21))
  assert_eq(roundtrip_stream(ReservedStream(1000000)), ReservedStream(1000000))
}

///|
test "http3 stream: a push stream carries its push id" {
  let wire = http3_encode_stream_type(PushStream(0x4000)) // 2-byte varint push id
  match http3_decode_stream_type(wire[:]) {
    Some((PushStream(id), _)) => assert_eq(id, 0x4000)
    _ => abort("expected a push stream")
  }
}

///|
test "http3 stream: a control stream opens with its type then SETTINGS" {
  let settings : Array[(UInt64, UInt64)] = [(0x06, 16384), (0x07, 100)]
  let wire = http3_encode_control_stream(settings)
  match http3_decode_stream_type(wire[:]) {
    Some((ControlStream, consumed)) => {
      let (frames, _) = http3_frame_decode_all(wire[consumed:].to_owned())
      assert_eq(frames, [Settings(settings)])
    }
    _ => abort("expected a control stream")
  }
}
