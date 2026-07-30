// TLS 1.3 client handshake state machine transitions (RFC 8446 Appendix A.1).

///|
test "client handshake: the full certificate-authenticated flight" {
  let s0 = TlsClientState::new()
  assert_eq(s0, WaitServerHello)
  let s1 = tls_client_next(s0, 2) // ServerHello
  assert_eq(s1, WaitEncryptedExtensions)
  let s2 = tls_client_next(s1, 8) // EncryptedExtensions
  assert_eq(s2, WaitCertCertReq)
  let s3 = tls_client_next(s2, 11) // Certificate (no CertificateRequest)
  assert_eq(s3, WaitCertVerify)
  let s4 = tls_client_next(s3, 15) // CertificateVerify
  assert_eq(s4, WaitFinished)
  let s5 = tls_client_next(s4, 20) // Finished
  assert_eq(s5, Connected)
}

///|
test "client handshake: the certificate-request branch" {
  let s = tls_client_next(tls_client_next(TlsClientState::new(), 2), 8) // WAIT_SH -> WAIT_EE -> WAIT_CERT_CR
  assert_eq(s, WaitCertCertReq)
  let with_req = tls_client_next(s, 13) // CertificateRequest
  assert_eq(with_req, WaitCert)
  let after_cert = tls_client_next(with_req, 11) // Certificate
  assert_eq(after_cert, WaitCertVerify)
}

///|
test "client handshake: an out-of-order message raises" {
  // A Finished before the ServerHello.
  let early_finished = try {
    let _ = tls_client_next(TlsClientState::new(), 20)
    false
  } catch {
    _ => true
  }
  assert_eq(early_finished, true)
  // Any message once connected.
  let s = tls_client_next(
    tls_client_next(
      tls_client_next(
        tls_client_next(tls_client_next(TlsClientState::new(), 2), 8),
        11,
      ),
      15,
    ),
    20,
  )
  assert_eq(s, Connected)
  let after_connected = try {
    let _ = tls_client_next(s, 8)
    false
  } catch {
    _ => true
  }
  assert_eq(after_connected, true)
}
