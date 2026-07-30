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
