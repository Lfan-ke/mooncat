// The TLS 1.3 server handshake state machine (RFC 8446 Appendix A.2). A server receives
// the ClientHello, negotiates and sends its whole flight (ServerHello, EncryptedExten-
// sions, an optional CertificateRequest, Certificate, CertificateVerify, Finished), then
// waits for the client's second flight: the client Certificate and CertificateVerify
// when client authentication was requested, and finally the client Finished. This models
// the full-handshake, certificate-authenticated path a mooncat server drives.

///|
/// A server's handshake state (RFC 8446 A.2).
pub(all) enum TlsServerState {
  Start
  RecvdClientHello
  WaitCert
  WaitCertVerify
  WaitFinished
  Connected
} derive(Eq, Debug)

///|
/// The initial state, awaiting the ClientHello.
pub fn TlsServerState::new() -> TlsServerState {
  Start
}

///|
/// The ClientHello handshake type (RFC 8446 §4), which the shared constants omit.
let tls_hs_client_hello : Int = 1

///|
/// The next server state on receiving a handshake message of `msg_type` (RFC 8446 A.2):
/// the ClientHello that opens the handshake, then the client's Certificate,
/// CertificateVerify, and Finished. An out-of-order message is an unexpected-message
/// error.
pub fn tls_server_recv(
  state : TlsServerState,
  msg_type : Int,
) -> TlsServerState raise StreamStateError {
  match (state, msg_type) {
    (Start, t) if t == tls_hs_client_hello => RecvdClientHello
    (WaitCert, t) if t == tls_hs_certificate => WaitCertVerify
    (WaitCertVerify, t) if t == tls_hs_certificate_verify => WaitFinished
    (WaitFinished, t) if t == tls_hs_finished => Connected
    _ => raise StreamStateError("unexpected TLS 1.3 handshake message (server)")
  }
}

///|
/// The server's own action after receiving the ClientHello: it negotiates and sends its
/// whole flight, then waits for the client's Certificate (when `request_client_cert` is
/// set) or straight for the client Finished. Sending the flight in any other state is an
/// error.
pub fn tls_server_send_flight(
  state : TlsServerState,
  request_client_cert : Bool,
) -> TlsServerState raise StreamStateError {
  match state {
    RecvdClientHello =>
      if request_client_cert {
        WaitCert
      } else {
        WaitFinished
      }
    _ =>
      raise StreamStateError(
        "server may only send its flight after ClientHello",
      )
  }
}
