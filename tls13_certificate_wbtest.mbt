// The TLS 1.3 Certificate message wire format (RFC 8446 §4.4.2).

///|
test "certificate message: a single certificate encodes to the exact RFC 8446 §4.4.2 wire form" {
  let der = b"der-cert-heke1228"
  let msg = tls13_encode_certificate(b"", [der])
  // context length 0x00, then the certificate_list length (3 bytes): one entry is
  // 3 (cert length) + 17 (DER) + 2 (extensions length) = 22 bytes.
  assert_eq(msg.length(), 1 + 3 + 3 + 17 + 2)
  assert_eq(msg[0], b'\x00') // empty certificate_request_context
  assert_eq(cert_read_u24(msg[:], 1), 22) // certificate_list length
  assert_eq(cert_read_u24(msg[:], 4), 17) // cert_data length
  assert_eq(msg[msg.length() - 2], b'\x00') // extensions length (2 bytes, empty)
  assert_eq(msg[msg.length() - 1], b'\x00')
  // Round-trip: an empty context and the one DER blob back out.
  assert_eq(tls13_decode_certificate(msg[:]), Some((b"", [der])))
}

///|
test "certificate message: a chain of certificates round-trips with its context" {
  let leaf = b"leaf-certificate-der-233"
  let intermediate = b"intermediate-ca-der-66666"
  let context = b"lfanke"
  let msg = tls13_encode_certificate(context, [leaf, intermediate])
  assert_eq(
    tls13_decode_certificate(msg[:]),
    Some((context, [leaf, intermediate])),
  )
  // Wrapped as a handshake message (type 11) and pulled back out of the flight.
  let hs = tls_encode_handshake(11, msg)
  let body = match tls_parse_handshake(hs[:]) {
    Some((11, b)) => b
    _ => abort("Certificate handshake did not parse")
  }
  assert_eq(
    tls13_decode_certificate(body[:]),
    Some((context, [leaf, intermediate])),
  )
}
