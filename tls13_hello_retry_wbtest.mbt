// HelloRetryRequest (RFC 8446 §4.1.4).

///|
test "hello retry: the sentinel random is the SHA-256 of \"HelloRetryRequest\"" {
  // RFC 8446 §4.1.3 gives the 32 bytes; they are that hash, so the constant is checked against
  // its derivation rather than against a copy of itself.
  assert_eq(tls13_hello_retry_random, sha256(b"HelloRetryRequest"))
  assert_eq(
    qv_hex(tls13_hello_retry_random),
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
  )
}

///|
test "hello retry: a group offered with no key share asks for one" {
  // The client lists x25519 in supported_groups but only sends a share for secp384r1, so the
  // group this build runs is usable and only the share is missing (§4.1.4).
  let ch = hello_offering([
    tls_supported_versions_extension([tls_version_13]),
    tls_supported_groups_extension([tls_group_secp384r1, tls_group_x25519]),
    tls_signature_algorithms_extension([tls_sig_ecdsa_secp256r1_sha256]),
    client_key_share([(tls_group_secp384r1, Bytes::make(97, b'\x04'))]),
  ])
  assert_eq(tls13_negotiate(ch), Retry(tls_group_x25519))
}

///|
test "hello retry: a ClientHello with no key share at all is still a missing_extension" {
  // §9.2 makes key_share mandatory; an absent extension is a malformed hello, not a retryable
  // one, and there is nothing to retry towards.
  let ch = hello_offering([
    tls_supported_versions_extension([tls_version_13]),
    tls_supported_groups_extension([tls_group_x25519]),
    tls_signature_algorithms_extension([tls_sig_ecdsa_secp256r1_sha256]),
  ])
  assert_eq(negotiation_alert(ch), Some(tls_fatal(tls_alert_missing_extension)))
}

///|
test "hello retry: the request is a ServerHello with the sentinel random and the bare group" {
  let hrr = tls13_hello_retry_request(b"heke1228", 0x1301, tls_group_x25519)
  let wire = encode_server_hello(hrr)
  guard tls_parse_handshake(wire[:]) is Some((msg_type, body)) else {
    fail("the HelloRetryRequest should frame")
  }
  // It travels as a ServerHello: same message type, same legacy_version (§4.1.4).
  assert_eq(msg_type, tls_server_hello)
  assert_eq(qv_hex(body[0:2].to_owned()), "0303")
  assert_eq(
    qv_hex(body[2:34].to_owned()),
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
  )
  guard decode_server_hello(body[:]) is Some(decoded) else {
    fail("the HelloRetryRequest should decode")
  }
  assert_eq(tls13_is_hello_retry_request(decoded), true)
  assert_eq(tls13_hello_retry_group(decoded), Some(tls_group_x25519))
  assert_eq(tls_server_hello_version(decoded), Some(tls_version_13))
  assert_eq(decoded.session_id, b"heke1228")
  assert_eq(decoded.cipher_suite, 0x1301)
  // §4.2.8: the key_share carries the group alone, with no key behind it.
  guard tls_find_extension(decoded.extensions, tls_ext_key_share)
    is Some(key_share) else {
    fail("the HelloRetryRequest should carry a key_share")
  }
  assert_eq(qv_hex(key_share.data), "001d")
  assert_eq(
    tls_decode_key_share_retry(key_share.data[:]),
    Some(tls_group_x25519),
  )
}

///|
test "hello retry: an ordinary ServerHello is not one" {
  let sh = tls13_server_hello(Bytes::make(32, b'\x23'), b"", 0x1301, [
    tls_key_share_extension(tls_group_x25519, a_client_share()),
  ])
  assert_eq(tls13_is_hello_retry_request(sh), false)
  assert_eq(tls13_hello_retry_group(sh), None)
  // The sentinel is what distinguishes them, so a real ServerHello's key_share must not read
  // as a group code even though both live under extension 0x0033.
  assert_eq(tls_decode_key_share_retry(b"\x00\x1d\x00\x20"[:]), None)
}

///|
test "hello retry: the driver negotiates the ClientHello it received" {
  let hs = TlsServerHandshake::new()
  let _ = hs.feed(qv_hexb(rfc8448_client_hello))
  assert_eq(
    hs.negotiate(),
    Negotiated(
      group=tls_group_x25519,
      client_key=qv_hexb(
        "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c",
      ),
      scheme=tls_sig_ecdsa_secp256r1_sha256,
    ),
  )
  // Before any ClientHello there is nothing to read, and saying so beats a silent `None`.
  let empty = try {
    let _ = TlsServerHandshake::new().negotiate()
    None
  } catch {
    a => Some(a)
  }
  assert_eq(empty, Some(tls_fatal(tls_alert_decode_error)))
}
