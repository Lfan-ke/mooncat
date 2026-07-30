// QUIC packet payload assembly (RFC 9000 §12.4, §13.2.1, §14.1): frame-list round trip,
// padding, ack-eliciting classification.

///|
test "payload: a frame list round-trips through encode and parse" {
  let frames : Array[QuicFrame] = [
    Ping,
    Crypto(offset=0, data=b"hello"),
    MaxData(1000),
    Ack(largest=5, delay=0, first_range=5, ranges=[]),
  ]
  let payload = quic_encode_payload(frames)
  assert_eq(quic_parse_payload(payload), frames)
}

///|
test "payload: trailing PADDING parses as one Padding frame" {
  // One PING then four zero octets.
  let payload = quic_pad_payload(quic_encode_payload([Ping]), 5)
  assert_eq(payload.length(), 5)
  assert_eq(quic_parse_payload(payload), [Ping, Padding(4)])
}

///|
test "payload: pad is a no-op when already long enough" {
  let payload = quic_encode_payload([Crypto(offset=0, data=b"abcdef")])
  let padded = quic_pad_payload(payload, 3)
  assert_eq(padded, payload)
}

///|
test "payload: ack-eliciting classification (RFC 9000 §13.2.1)" {
  // ACK, PADDING, CONNECTION_CLOSE are not ack-eliciting; everything else is.
  assert_eq(quic_frame_is_ack_eliciting(Ping), true)
  assert_eq(
    quic_frame_is_ack_eliciting(
      Ack(largest=0, delay=0, first_range=0, ranges=[]),
    ),
    false,
  )
  assert_eq(quic_frame_is_ack_eliciting(Padding(4)), false)
  assert_eq(
    quic_frame_is_ack_eliciting(
      ConnectionClose(error_code=0, frame_type=None, reason=b""),
    ),
    false,
  )
  // A payload of only ACK + PADDING is not ack-eliciting; adding any other frame is.
  assert_eq(
    quic_payload_is_ack_eliciting([
      Ack(largest=0, delay=0, first_range=0, ranges=[]),
      Padding(2),
    ]),
    false,
  )
  assert_eq(
    quic_payload_is_ack_eliciting([
      Ack(largest=0, delay=0, first_range=0, ranges=[]),
      Ping,
    ]),
    true,
  )
}

///|
test "payload: an empty payload has no frames" {
  assert_eq(quic_parse_payload(b""), [])
}

///|
test "payload: a truncated frame raises" {
  // A CRYPTO frame (type 0x06) with an offset but a length that overruns the buffer.
  let truncated = try {
    let _ = quic_parse_payload(b"\x06\x00\x0a\x68\x69")
    false
  } catch {
    _ => true
  }
  assert_eq(truncated, true)
}
