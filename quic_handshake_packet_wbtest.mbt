// QUIC Handshake packet protection (RFC 9000 §17.2.4, RFC 9001 §5.3–§5.4): a long-header
// packet with the Handshake type and no token field, carrying the handshake flight in
// CRYPTO frames under the handshake-space keys.

///|
/// The server handshake-space keys from the RFC 8448 §3 key schedule (the traffic secret
/// and its packet keys are checked in quic_hs_keys_wbtest). A Handshake packet the server
/// sends is protected with these; the client derives the same keys to open it.
fn rfc8448_server_hs_keys() -> QuicPacketKeys {
  let handshake = qv_hexb(
    "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
  )
  let hs_th = qv_hexb(
    "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8",
  )
  quic_handshake_keys(handshake, hs_th, false)
}

///|
test "handshake packet: a server flight round-trips under the handshake keys" {
  let keys = rfc8448_server_hs_keys()
  let dcid = qv_hexb("0001020304050607")
  let scid = qv_hexb("f0f1f2f3")
  let frames : Array[QuicFrame] = [
    Crypto(
      offset=0,
      data=b"encrypted-extensions..certificate..cert-verify..finished",
    ),
    Ping,
  ]
  let packet = quic_send_handshake(1U, dcid, scid, 7, 4, frames, keys)
  match quic_recv_handshake(packet, keys) {
    Some((got, pn)) => {
      assert_eq(pn, 7)
      assert_eq(got, frames)
    }
    None => abort("Handshake packet failed to authenticate")
  }
}

///|
test "handshake packet: the pn offset walks the token-less long header" {
  let keys = rfc8448_server_hs_keys()
  let dcid = qv_hexb("0001020304050607") // 8 bytes
  let scid = qv_hexb("f0f1f2f3") // 4 bytes
  let packet = quic_send_handshake(
    1U,
    dcid,
    scid,
    0,
    4,
    [Crypto(offset=0, data=b"flight")],
    keys,
  )
  // first byte(1) + version(4) + dcid_len(1)+dcid(8) + scid_len(1)+scid(4) + length varint(1)
  assert_eq(quic_handshake_pn_offset(packet), 1 + 4 + 1 + 8 + 1 + 4 + 1)
}

///|
test "handshake packet: a tampered packet is rejected" {
  let keys = rfc8448_server_hs_keys()
  let dcid = qv_hexb("0001020304050607")
  let scid = qv_hexb("f0f1f2f3")
  let packet = quic_send_handshake(
    1U,
    dcid,
    scid,
    3,
    4,
    [Crypto(offset=0, data=b"flight")],
    keys,
  )
  let buf = Buffer()
  for i = 0; i < packet.length(); i = i + 1 {
    if i == packet.length() - 1 {
      buf.write_byte((packet[i].to_int() ^ 0xff).to_byte())
    } else {
      buf.write_byte(packet[i])
    }
  }
  match quic_recv_handshake(buf.to_bytes(), keys) {
    Some(_) => abort("a tampered Handshake packet must not authenticate")
    None => ()
  }
}
