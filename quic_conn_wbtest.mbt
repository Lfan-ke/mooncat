// QUIC connection numbering/handshake-input core (RFC 9000 §12.3, RFC 9001 §4.1.3): the
// three packet-number spaces number and acknowledge independently, and each encryption
// level's CRYPTO stream reassembles on its own.

///|
test "conn: packet-number spaces are independent" {
  let c = QuicConnection::new(false)
  assert_eq(c.is_server(), false)
  // Send numbers advance per space.
  assert_eq(c.next_packet_number(QuicLevel::Initial), 0)
  assert_eq(c.next_packet_number(QuicLevel::Initial), 1)
  assert_eq(c.next_packet_number(QuicLevel::Handshake), 0)
  assert_eq(c.next_packet_number(QuicLevel::Application), 0)
}

///|
test "conn: a received packet is acknowledged only in its own space" {
  let c = QuicConnection::new(true)
  c.on_packet_received(QuicLevel::Initial, 0, true)
  c.on_packet_received(QuicLevel::Initial, 1, true)
  // Initial owes an ACK covering 0..1; Handshake has received nothing.
  match c.build_ack(QuicLevel::Initial, 0) {
    Some(Ack(largest~, first_range~, ..)) => {
      assert_eq(largest, 1)
      assert_eq(first_range, 1)
    }
    _ => abort("expected an Initial ACK")
  }
  assert_eq(c.build_ack(QuicLevel::Handshake, 0), None)
}

///|
test "conn: the largest acknowledged is tracked per space" {
  let c = QuicConnection::new(false)
  c.on_ack_received(QuicLevel::Handshake, 7)
  assert_eq(c.space(QuicLevel::Handshake).largest_acked(), Some(7))
  assert_eq(c.space(QuicLevel::Initial).largest_acked(), None)
}

///|
test "conn: CRYPTO frames reassemble per level, out of order" {
  let c = QuicConnection::new(false)
  // Initial CRYPTO: the tail arrives first, then the head fills the gap.
  assert_eq(c.on_crypto_frame(QuicLevel::Initial, 3, b"def"), b"")
  assert_eq(c.on_crypto_frame(QuicLevel::Initial, 0, b"abc"), b"abcdef")
  // Handshake CRYPTO is a separate stream, still at offset 0.
  assert_eq(c.on_crypto_frame(QuicLevel::Handshake, 0, b"TLS"), b"TLS")
  // The Initial stream continues from where it left off.
  assert_eq(c.on_crypto_frame(QuicLevel::Initial, 6, b"ghi"), b"ghi")
}

///|
test "conn: a CRYPTO gap holds back later handshake bytes" {
  let c = QuicConnection::new(true)
  assert_eq(c.on_crypto_frame(QuicLevel::Handshake, 2, b"cd"), b"")
  assert_eq(c.on_crypto_frame(QuicLevel::Handshake, 0, b"ab"), b"abcd")
}
