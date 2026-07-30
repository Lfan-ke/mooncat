// A full QUIC Initial packet round trip (RFC 9001 §5): the sender derives the Initial
// keys from the connection id, protects a frame payload, and the receiver — sharing the
// same Initial secret — recovers the frames and packet number. A tampered packet fails
// to authenticate.

///|
test "Initial packet: protect then parse recovers the frames with derived keys" {
  let dcid = qv_hexb("8394c8f03e515708")
  let scid = qv_hexb("0102030405")
  let keys = quic_packet_keys(quic_client_initial_secret(dcid))
  let frames : Array[QuicFrame] = [
    Crypto(offset=0, data=b"CLIENTHELLO-bytes"),
    Ping,
  ]
  let packet = quic_send_initial(1U, dcid, scid, b"", 2, 4, frames, keys)
  // The receiver shares the Initial keys (derived from the same DCID).
  match quic_recv_initial(packet, keys) {
    Some((recovered, pn)) => {
      assert_eq(pn, 2)
      assert_eq(recovered, frames)
    }
    None => abort("Initial packet failed to authenticate")
  }
}

///|
test "Initial packet: the packet-number offset lands after the length field" {
  let dcid = qv_hexb("8394c8f03e515708")
  let scid = qv_hexb("0102030405")
  let keys = quic_packet_keys(quic_client_initial_secret(dcid))
  let packet = quic_send_initial(1U, dcid, scid, b"", 0, 4, [Ping], keys)
  // 1 (first byte) + 4 (version) + 1 + 8 (DCID) + 1 + 5 (SCID) + 1 (token len 0) +
  // 1 (length varint: value 21 fits one byte) = 22.
  assert_eq(quic_initial_pn_offset(packet), 22)
}

///|
test "Initial packet: tampering breaks authentication" {
  let dcid = qv_hexb("8394c8f03e515708")
  let keys = quic_packet_keys(quic_client_initial_secret(dcid))
  let packet = quic_send_initial(
    1U,
    dcid,
    b"",
    b"",
    1,
    4,
    [Crypto(offset=0, data=b"hello")],
    keys,
  )
  // Flip the last byte of the ciphertext so the AEAD tag no longer verifies.
  let buf = Buffer()
  for i = 0; i < packet.length(); i = i + 1 {
    if i == packet.length() - 1 {
      buf.write_byte((packet[i].to_int() ^ 0xff).to_byte())
    } else {
      buf.write_byte(packet[i])
    }
  }
  assert_eq(quic_recv_initial(buf.to_bytes(), keys), None)
}
