// The QUIC UDP datagram transport over a real async socket (RFC 9000 §5): a loopback
// round-trip proving an endpoint can bind, receive a datagram with its sender's address,
// and send one back.

///|
async test "quic udp: a datagram round-trips over a real async UDP socket (loopback)" {
  @async.with_task_group(g => {
    let server = QuicUdpEndpoint::bind("127.0.0.1:0")
    let server_addr = server.local_addr()
    // Server task: receive one datagram and echo it back to its sender.
    let _ = g.spawn(() => {
      let (data, from) = server.recv_datagram()
      server.send_datagram(data, from)
    })
    @async.sleep(100)
    let client = QuicUdpEndpoint::bind("127.0.0.1:0")
    let payload = b"quic-initial-packet-probe"
    client.send_datagram(payload, server_addr)
    let (echo, _from) = client.recv_datagram()
    assert_eq(echo, payload)
    client.close()
    server.close()
  })
}

///|
async test "quic over udp: a real Initial packet with a ClientHello drives the server handshake over the wire" {
  @async.with_task_group(g => {
    let dcid = qv_hexb("8394c8f03e515708")
    let server_ep = QuicUdpEndpoint::bind("127.0.0.1:0")
    let server_addr = server_ep.local_addr()
    let server_conn = QuicServerConn::new(dcid)
    let processed : Ref[Array[Int]] = { val: [] }
    // Server task: receive one datagram and drive the handshake with it.
    let _ = g.spawn(() => {
      let (datagram, _from) = server_ep.recv_datagram()
      processed.val = server_conn.receive_initial(datagram) catch { _ => [] }
    })
    @async.sleep(100)
    // Client: build a real protected Initial packet carrying a ClientHello and send it.
    let client_ep = QuicUdpEndpoint::bind("127.0.0.1:0")
    let keys = client_initial_keys(dcid)
    let ch = tls_encode_handshake(1, b"clienthello-over-real-udp")
    let initial = quic_send_initial(
      1U,
      dcid,
      b"",
      b"",
      0,
      4,
      [Crypto(offset=0, data=ch)],
      keys,
    )
    client_ep.send_datagram(initial, server_addr)
    @async.sleep(200)
    // The server decrypted the Initial with keys derived from the DCID and advanced.
    assert_eq(processed.val, [1])
    assert_eq(server_conn.handshake_state(), RecvdClientHello)
    assert_eq(server_conn.initial_ack_pending(), true)
    client_ep.close()
    server_ep.close()
  })
}

///|
async test "quic over udp: client ClientHello and server ServerHello complete an Initial flight over the wire" {
  @async.with_task_group(g => {
    let dcid = qv_hexb("8394c8f03e515708")
    let server_ep = QuicUdpEndpoint::bind("127.0.0.1:0")
    let server_addr = server_ep.local_addr()
    let server_conn = QuicServerConn::new(dcid)
    // Server task: receive the ClientHello, then send back a protected ServerHello Initial
    // packet to the client's address.
    let _ = g.spawn(() => {
      let (datagram, client_addr) = server_ep.recv_datagram()
      let _ = server_conn.receive_initial(datagram) catch { _ => [] }
      let sh = TlsServerHello::{
        random: Bytes::make(32, b'\xab'),
        session_id: b"",
        cipher_suite: 0x1301,
        extensions: [],
      }
      let sh_packet = server_conn.send_server_hello(
        sh, b"", b"\x01\x02\x03\x04", 0,
      )
      server_ep.send_datagram(sh_packet, client_addr)
    })
    @async.sleep(100)
    let client_ep = QuicUdpEndpoint::bind("127.0.0.1:0")
    let keys = client_initial_keys(dcid)
    let initial = quic_send_initial(
      1U,
      dcid,
      b"",
      b"",
      0,
      4,
      [Crypto(offset=0, data=tls_encode_handshake(1, b"ch"))],
      keys,
    )
    client_ep.send_datagram(initial, server_addr)
    // Receive the server's ServerHello Initial packet and decode it.
    let (sh_datagram, _) = client_ep.recv_datagram()
    let decoded = match quic_recv_initial(sh_datagram, keys) {
      Some((frames, _)) => {
        let mut result : TlsServerHello? = None
        for frame in frames {
          match frame {
            Crypto(data~, ..) =>
              match tls_parse_handshake(data[:]) {
                Some((2, body)) => result = decode_server_hello(body[:])
                _ => ()
              }
            _ => ()
          }
        }
        result
      }
      None => None
    }
    match decoded {
      Some(sh) => assert_eq(sh.cipher_suite, 0x1301)
      None =>
        abort("client did not receive a decodable ServerHello over the wire")
    }
    client_ep.close()
    server_ep.close()
  })
}
