// The TLS 1.3 server handshake runner (RFC 8446 §4): it drives the server state machine
// over the CRYPTO byte stream. `feed` appends received CRYPTO bytes, splits off every
// complete handshake message, adds each to the running transcript, and advances the
// state machine; a trailing partial message is buffered for the next feed. The server's
// own flight is folded in with `record_sent` (so the transcript stays in message order)
// and `sent_flight` (advancing the state past the send). This ties the handshake-message
// framing, the transcript hash, and the state machine into the driver a QUIC/TLS server
// keeps as it processes the handshake — a pure core; the keys and socket wrap it.

///|
/// A server-side TLS 1.3 handshake in progress.
pub struct TlsServerHandshake {
  mut state : TlsServerState
  transcript : TranscriptHash
  mut buffer : Bytes
  mut client_hello : Bytes
}

///|
/// A fresh handshake, awaiting the ClientHello.
pub fn TlsServerHandshake::new() -> TlsServerHandshake {
  {
    state: Start,
    transcript: TranscriptHash::new(),
    buffer: b"",
    client_hello: b"",
  }
}

///|
/// The current handshake state.
pub fn TlsServerHandshake::state(self : TlsServerHandshake) -> TlsServerState {
  self.state
}

///|
/// The running transcript hash over every message seen so far, in order.
pub fn TlsServerHandshake::transcript_hash(self : TlsServerHandshake) -> Bytes {
  self.transcript.hash()
}

///|
/// Whether the handshake has completed.
pub fn TlsServerHandshake::is_connected(self : TlsServerHandshake) -> Bool {
  self.state == Connected
}

///|
/// The raw ClientHello message the handshake received (empty until one arrives). A server
/// needs it to pull the client's key_share and run the ECDHE that derives the handshake
/// secrets.
pub fn TlsServerHandshake::client_hello(self : TlsServerHandshake) -> Bytes {
  self.client_hello
}

///|
/// Feed received CRYPTO bytes: process every complete handshake message now available —
/// add it to the transcript and drive the state machine — buffering any trailing partial
/// message. Returns the handshake types processed, in order.
pub fn TlsServerHandshake::feed(
  self : TlsServerHandshake,
  bytes : Bytes,
) -> Array[Int] raise {
  self.buffer = bytes_concat(self.buffer, bytes)
  let processed : Array[Int] = []
  let view = self.buffer[:]
  let mut off = 0
  for ;; {
    match tls_parse_handshake(view[off:]) {
      Some((msg_type, body)) => {
        let consumed = 4 + body.length()
        let message = view[off:off + consumed].to_owned()
        if msg_type == tls_client_hello {
          self.client_hello = message
        }
        self.transcript.add(message)
        self.state = tls_server_recv(self.state, msg_type)
        processed.push(msg_type)
        off = off + consumed
      }
      None => break
    }
  }
  self.buffer = view[off:view.length()].to_owned()
  processed
}

///|
/// Fold a handshake message the server sends (ServerHello, EncryptedExtensions,
/// Certificate, ...) into the transcript, keeping it in message order.
pub fn TlsServerHandshake::record_sent(
  self : TlsServerHandshake,
  message : Bytes,
) -> Unit {
  self.transcript.add(message)
}

///|
/// Advance the state machine past the server's own flight (after the ClientHello),
/// waiting for a client certificate when `request_client_cert` is set.
pub fn TlsServerHandshake::sent_flight(
  self : TlsServerHandshake,
  request_client_cert : Bool,
) -> Unit raise {
  self.state = tls_server_send_flight(self.state, request_client_cert)
}
