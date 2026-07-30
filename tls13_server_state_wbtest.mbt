// TLS 1.3 server handshake state machine transitions (RFC 8446 Appendix A.2).

///|
test "server handshake: no client authentication" {
  let s0 = TlsServerState::new()
  assert_eq(s0, Start)
  let s1 = tls_server_recv(s0, 1) // ClientHello
  assert_eq(s1, RecvdClientHello)
  // Server sends its flight without requesting a client certificate.
  let s2 = tls_server_send_flight(s1, false)
  assert_eq(s2, WaitFinished)
  let s3 = tls_server_recv(s2, 20) // client Finished
  assert_eq(s3, Connected)
}

///|
test "server handshake: mutual authentication (client certificate requested)" {
  let s1 = tls_server_recv(TlsServerState::new(), 1) // ClientHello
  let s2 = tls_server_send_flight(s1, true) // request client cert
  assert_eq(s2, WaitCert)
  let s3 = tls_server_recv(s2, 11) // client Certificate
  assert_eq(s3, WaitCertVerify)
  let s4 = tls_server_recv(s3, 15) // client CertificateVerify
  assert_eq(s4, WaitFinished)
  let s5 = tls_server_recv(s4, 20) // client Finished
  assert_eq(s5, Connected)
}

///|
test "server handshake: out-of-order messages and premature sends raise" {
  // A Finished before the ClientHello.
  let early = try {
    let _ = tls_server_recv(TlsServerState::new(), 20)
    false
  } catch {
    _ => true
  }
  assert_eq(early, true)
  // Sending the flight before the ClientHello arrives.
  let premature_send = try {
    let _ = tls_server_send_flight(TlsServerState::new(), false)
    false
  } catch {
    _ => true
  }
  assert_eq(premature_send, true)
  // A Certificate when none was requested (state went straight to WaitFinished).
  let s = tls_server_send_flight(
    tls_server_recv(TlsServerState::new(), 1),
    false,
  )
  let unexpected_cert = try {
    let _ = tls_server_recv(s, 11)
    false
  } catch {
    _ => true
  }
  assert_eq(unexpected_cert, true)
}
