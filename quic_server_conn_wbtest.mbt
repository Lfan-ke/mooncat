// A QUIC server processing a client's Initial flight end to end (RFC 9001 §5): a real
// protected Initial packet carrying a ClientHello in a CRYPTO frame advances the server
// handshake to RECVD_CH; a ClientHello split across two packets reassembles first.

///|
/// The Initial packet keys a client uses toward a server, both derived from `dcid`.
fn client_initial_keys(dcid : Bytes) -> QuicPacketKeys {
  quic_packet_keys(quic_client_initial_secret(dcid))
}

///|
test "server conn: a ClientHello in one Initial packet reaches RECVD_CH" {
  let dcid = qv_hexb("8394c8f03e515708")
  let keys = client_initial_keys(dcid)
  let ch = tls_encode_handshake(1, b"clienthello-body")
  let packet = quic_send_initial(
    1U,
    dcid,
    b"",
    b"",
    0,
    4,
    [Crypto(offset=0, data=ch)],
    keys,
  )
  let server = QuicServerConn::new(dcid)
  assert_eq(server.receive_initial(packet), [1])
  assert_eq(server.handshake_state(), RecvdClientHello)
  // The ack-eliciting Initial owes an ACK.
  assert_eq(server.initial_ack_pending(), true)
}

///|
test "server conn: a ClientHello split across two Initial packets reassembles" {
  let dcid = qv_hexb("0001020304050607")
  let keys = client_initial_keys(dcid)
  let ch = tls_encode_handshake(1, b"a-longer-clienthello-body")
  let first = ch[0:15].to_owned()
  let rest = ch[15:ch.length()].to_owned()
  let packet1 = quic_send_initial(
    1U,
    dcid,
    b"",
    b"",
    0,
    4,
    [Crypto(offset=0, data=first)],
    keys,
  )
  let packet2 = quic_send_initial(
    1U,
    dcid,
    b"",
    b"",
    1,
    4,
    [Crypto(offset=15, data=rest)],
    keys,
  )
  let server = QuicServerConn::new(dcid)
  // The first packet delivers only a partial handshake message: nothing processed yet.
  assert_eq(server.receive_initial(packet1), [])
  assert_eq(server.handshake_state(), Start)
  // The second packet completes it.
  assert_eq(server.receive_initial(packet2), [1])
  assert_eq(server.handshake_state(), RecvdClientHello)
}

///|
test "server conn: a tampered Initial packet is rejected" {
  let dcid = qv_hexb("8394c8f03e515708")
  let keys = client_initial_keys(dcid)
  let packet = quic_send_initial(
    1U,
    dcid,
    b"",
    b"",
    0,
    4,
    [Crypto(offset=0, data=tls_encode_handshake(1, b"ch"))],
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
  let server = QuicServerConn::new(dcid)
  let rejected = try {
    let _ = server.receive_initial(buf.to_bytes())
    false
  } catch {
    _ => true
  }
  assert_eq(rejected, true)
}
