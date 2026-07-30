// A QUIC server connection's Initial-flight processing (RFC 9000 §7, RFC 9001 §5): it
// ties the Initial packet protection, the per-level CRYPTO reassembly, and the TLS 1.3
// handshake runner together. Receiving an Initial packet unprotects it with the keys
// derived from the client's connection id, records the packet number for acknowledgement,
// reassembles the CRYPTO stream, and drives the handshake with the contiguous handshake
// bytes. This is the pure connection core the async UDP transport wraps; feeding it a
// client's Initial packet advances the server handshake to RECVD_CH.

///|
/// A QUIC server connection mid-handshake: the Initial keys, the packet-number/CRYPTO
/// bookkeeping, and the TLS handshake it is driving.
pub struct QuicServerConn {
  initial_keys : QuicPacketKeys
  handshake : TlsServerHandshake
  conn : QuicConnection
}

///|
/// A server connection for a client whose Destination Connection ID is `dcid` (the
/// Initial secret and keys derive from it, RFC 9001 §5.2).
pub fn QuicServerConn::new(dcid : Bytes) -> QuicServerConn {
  {
    initial_keys: quic_packet_keys(quic_client_initial_secret(dcid)),
    handshake: TlsServerHandshake::new(),
    conn: QuicConnection::new(true),
  }
}

///|
/// The current TLS handshake state.
pub fn QuicServerConn::handshake_state(self : QuicServerConn) -> TlsServerState {
  self.handshake.state()
}

///|
/// The transcript hash over the handshake messages processed so far.
pub fn QuicServerConn::transcript_hash(self : QuicServerConn) -> Bytes {
  self.handshake.transcript_hash()
}

///|
/// Whether an ACK is owed in the Initial space.
pub fn QuicServerConn::initial_ack_pending(self : QuicServerConn) -> Bool {
  self.conn.space(QuicLevel::Initial).ack_pending()
}

///|
/// Build the server's ServerHello response: encode it, fold it into the transcript,
/// advance the state past the server flight (a full handshake, no client certificate
/// requested), and protect it into an Initial packet addressed to `out_dcid` (the
/// client's source connection id) from `out_scid`, at Initial packet number `pn`
/// (RFC 9001 §5.3). The Handshake-space messages follow separately once the handshake
/// keys are in use.
pub fn QuicServerConn::send_server_hello(
  self : QuicServerConn,
  server_hello : TlsServerHello,
  out_dcid : Bytes,
  out_scid : Bytes,
  pn : Int64,
) -> Bytes raise {
  let sh_msg = encode_server_hello(server_hello)
  self.handshake.record_sent(sh_msg)
  self.handshake.sent_flight(false)
  quic_send_initial(
    1U,
    out_dcid,
    out_scid,
    b"",
    pn,
    4,
    [Crypto(offset=0, data=sh_msg)],
    self.initial_keys,
  )
}

///|
/// Receive a client Initial packet: unprotect it, record its number for acknowledgement,
/// reassemble its CRYPTO frames, and drive the handshake with the contiguous handshake
/// bytes. Returns the handshake message types processed. Raises if the packet fails to
/// authenticate.
pub fn QuicServerConn::receive_initial(
  self : QuicServerConn,
  packet : Bytes,
) -> Array[Int] raise {
  let (frames, pn) = match quic_recv_initial(packet, self.initial_keys) {
    Some(v) => v
    None => raise QuicPayloadError("Initial packet failed to authenticate")
  }
  self.conn.on_packet_received(
    QuicLevel::Initial,
    pn,
    quic_payload_is_ack_eliciting(frames),
  )
  let processed : Array[Int] = []
  for frame in frames {
    match frame {
      Crypto(offset~, data~) => {
        let contiguous = self.conn.on_crypto_frame(
          QuicLevel::Initial,
          offset,
          data,
        )
        if contiguous.length() > 0 {
          for msg_type in self.handshake.feed(contiguous) {
            processed.push(msg_type)
          }
        }
      }
      _ => ()
    }
  }
  processed
}
