// Binding the QUIC datagram transport to moonbitlang/async's UDP socket (RFC 9000 §5): a
// QUIC endpoint is a UDP socket that receives and sends whole datagrams, each carrying one
// or more QUIC packets. This wraps `@socket.UdpServer` — which can both receive from and
// send to arbitrary peers, exactly the connectionless model QUIC needs — behind the two
// operations the connection loop drives: pull the next datagram (with its sender's address)
// and push a datagram to a peer. The packet protection, handshake, and HTTP/3 codecs run on
// the bytes these move; this is the seam where they meet a real socket.

///|
/// A QUIC UDP endpoint: a bound datagram socket.
pub struct QuicUdpEndpoint {
  server : @socket.UdpServer
}

///|
/// Bind an endpoint to `addr` (e.g. `"0.0.0.0:443"`, or `"127.0.0.1:0"` for an OS-assigned
/// port). The bound address is available from `local_addr`.
pub async fn QuicUdpEndpoint::bind(addr : String) -> QuicUdpEndpoint {
  { server: @socket.UdpServer::UdpServer(@socket.Addr::parse(addr)) }
}

///|
/// The address the endpoint is bound to (the concrete port when bound to port 0).
pub fn QuicUdpEndpoint::local_addr(self : QuicUdpEndpoint) -> @socket.Addr {
  self.server.addr
}

///|
/// Receive the next datagram and its sender's address, copying up to `max` bytes.
pub async fn QuicUdpEndpoint::recv_datagram(
  self : QuicUdpEndpoint,
  max? : Int = 2048,
) -> (Bytes, @socket.Addr) {
  let buf = FixedArray::make(max, b'\x00')
  let (n, from) = self.server.recvfrom(buf)
  let out = Buffer()
  for i = 0; i < n; i = i + 1 {
    out.write_byte(buf[i])
  }
  (out.to_bytes(), from)
}

///|
/// Send `data` as a single datagram to `to`.
pub async fn QuicUdpEndpoint::send_datagram(
  self : QuicUdpEndpoint,
  data : Bytes,
  to : @socket.Addr,
) -> Unit {
  self.server.sendto(data, to)
}

///|
/// Close the endpoint's socket.
pub fn QuicUdpEndpoint::close(self : QuicUdpEndpoint) -> Unit {
  self.server.close()
}
