// The extensions a real TLS 1.3 hello carries: the three RFC 8446 §9.2 makes mandatory
// alongside key_share, and the ALPN and QUIC transport parameters a HTTP/3 handshake threads
// through (RFC 8446 §4.3.1, RFC 9001 §8.2). The worked messages in RFC 8448 §3 are the
// reference the codecs are held to.

///|
test "hello extensions: a ClientHello carries key_share, ALPN, and transport parameters together" {
  let client_priv = qv_hexb(
    "2333333333333333333333333333333333333333333333333333333333333333",
  )
  let client_pub = tls13_x25519_public(client_priv)
  let params = [
    transport_param_int(tp_initial_max_data, 66666),
    transport_param_int(tp_initial_max_streams_bidi, 233),
  ]
  let ch = TlsClientHello::{
    random: Bytes::make(32, b'\x23'),
    session_id: b"lfanke",
    cipher_suites: [0x1301],
    extensions: [
      {
        ext_type: tls_ext_key_share,
        data: tls_encode_key_share_client([(tls_group_x25519, client_pub)]),
      },
      tls_alpn_extension(["h3", "h2"]),
      tls_quic_transport_params_extension(params),
    ],
  }
  // Round-trip the ClientHello and read every extension back off the decoded message.
  let ch_body = match tls_parse_handshake(encode_client_hello(ch)[:]) {
    Some((1, body)) => body
    _ => abort("ClientHello handshake did not parse")
  }
  let decoded = match decode_client_hello(ch_body[:]) {
    Some(v) => v
    None => abort("ClientHello did not decode")
  }
  assert_eq(
    tls_client_hello_key_shares(decoded.extensions)[0].0,
    tls_group_x25519,
  )
  assert_eq(tls_client_hello_alpn(decoded.extensions), ["h3", "h2"])
  assert_eq(tls_hello_quic_transport_params(decoded.extensions), params)
}

///|
test "hello extensions: a QUIC server's EncryptedExtensions carry the selected ALPN and its transport parameters" {
  let params = [
    transport_param_int(tp_initial_max_data, 66666),
    transport_param_int(tp_initial_max_stream_data_bidi_local, 23333),
    transport_param_int(tp_active_connection_id_limit, 8),
  ]
  let ee_body = tls13_quic_encrypted_extensions(alpn_h3, params)
  // The client decodes the EncryptedExtensions and reads the negotiated protocol and limits.
  let exts = match tls13_decode_encrypted_extensions(ee_body[:]) {
    Some(v) => v
    None => abort("EncryptedExtensions did not decode")
  }
  assert_eq(tls_selected_alpn(exts), Some("h3"))
  assert_eq(tls_hello_quic_transport_params(exts), params)
}

///|
/// A ClientHello with the fixed fields filled in, carrying `exts`.
fn hello_offering(exts : Array[TlsExtension]) -> TlsClientHello {
  {
    random: Bytes::make(32, b'\x23'),
    session_id: b"heke1228",
    cipher_suites: [0x1301],
    extensions: exts,
  }
}

///|
/// A ClientHello key_share extension offering one share per entry.
fn client_key_share(entries : Array[(Int, Bytes)]) -> TlsExtension {
  { ext_type: tls_ext_key_share, data: tls_encode_key_share_client(entries), }
}

///|
/// The alert `tls13_negotiate` refuses `ch` with, or `None` if it accepts it.
fn negotiation_alert(ch : TlsClientHello) -> TlsAlert? {
  try {
    let _ = tls13_negotiate(ch)
    None
  } catch {
    a => Some(a)
  }
}

///|
/// A well-formed x25519 share for a throwaway private key.
fn a_client_share() -> Bytes {
  tls13_x25519_public(
    qv_hexb("2333333333333333333333333333333333333333333333333333333333333333"),
  )
}

///|
test "hello extensions: a ClientHello carrying supported_versions, supported_groups and signature_algorithms round-trips" {
  let ch = hello_offering([
    tls_supported_versions_extension([tls_version_13, tls_legacy_version]),
    tls_supported_groups_extension([tls_group_x25519, tls_group_secp256r1]),
    tls_signature_algorithms_extension([
      tls_sig_ecdsa_secp256r1_sha256, tls_sig_rsa_pss_rsae_sha256,
    ]),
    client_key_share([(tls_group_x25519, a_client_share())]),
  ])
  let wire = encode_client_hello(ch)
  guard tls_parse_handshake(wire[:]) is Some((msg_type, body)) else {
    fail("the ClientHello should frame")
  }
  assert_eq(msg_type, tls_client_hello)
  guard decode_client_hello(body[:]) is Some(decoded) else {
    fail("the ClientHello should decode")
  }
  assert_eq(tls_client_hello_versions(decoded.extensions), [
    tls_version_13, tls_legacy_version,
  ])
  assert_eq(tls_client_hello_groups(decoded.extensions), [
    tls_group_x25519, tls_group_secp256r1,
  ])
  assert_eq(tls_client_hello_signature_algorithms(decoded.extensions), [
    tls_sig_ecdsa_secp256r1_sha256, tls_sig_rsa_pss_rsae_sha256,
  ])
  assert_eq(encode_client_hello(decoded), wire)
}

///|
test "hello extensions: RFC 8448 §3's ClientHello decodes to the three extension bodies its bytes hold" {
  guard tls_parse_handshake(qv_hexb(rfc8448_client_hello)[:]) is Some((_, body)) else {
    fail("the RFC 8448 ClientHello should frame")
  }
  guard decode_client_hello(body[:]) is Some(ch) else {
    fail("the RFC 8448 ClientHello should decode")
  }
  // supported_versions: `02 0304` — one version, TLS 1.3.
  guard tls_find_extension(ch.extensions, tls_ext_supported_versions)
    is Some(versions) else {
    fail("the RFC 8448 ClientHello should carry supported_versions")
  }
  assert_eq(qv_hex(versions.data), "020304")
  assert_eq(tls_client_hello_versions(ch.extensions), [tls_version_13])
  // supported_groups: `0012` then nine named groups.
  guard tls_find_extension(ch.extensions, tls_ext_supported_groups)
    is Some(groups) else {
    fail("the RFC 8448 ClientHello should carry supported_groups")
  }
  assert_eq(qv_hex(groups.data), "0012001d00170018001901000101010201030104")
  assert_eq(tls_client_hello_groups(ch.extensions), [
    0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
  ])
  // signature_algorithms: `001e` then fifteen schemes, ES256 first.
  guard tls_find_extension(ch.extensions, tls_ext_signature_algorithms)
    is Some(schemes) else {
    fail("the RFC 8448 ClientHello should carry signature_algorithms")
  }
  assert_eq(
    qv_hex(schemes.data),
    "001e040305030603020308040805080604010501060102010402050206020202",
  )
  assert_eq(tls_client_hello_signature_algorithms(ch.extensions), [
    0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
    0x0201, 0x0402, 0x0502, 0x0602, 0x0202,
  ])
  // Re-encoding each decoded list reproduces the RFC's bytes.
  assert_eq(
    qv_hex(
      tls_encode_supported_versions_client(
        tls_client_hello_versions(ch.extensions),
      ),
    ),
    qv_hex(versions.data),
  )
  assert_eq(
    qv_hex(tls_encode_supported_groups(tls_client_hello_groups(ch.extensions))),
    qv_hex(groups.data),
  )
  assert_eq(
    qv_hex(
      tls_encode_signature_algorithms(
        tls_client_hello_signature_algorithms(ch.extensions),
      ),
    ),
    qv_hex(schemes.data),
  )
}

///|
test "hello extensions: a ServerHello says 1.3 in supported_versions while legacy_version stays 1.2" {
  let sh = tls13_server_hello(Bytes::make(32, b'\x23'), b"", 0x1301, [
    tls_key_share_extension(tls_group_x25519, a_client_share()),
  ])
  let wire = encode_server_hello(sh)
  guard tls_parse_handshake(wire[:]) is Some((msg_type, body)) else {
    fail("the ServerHello should frame")
  }
  assert_eq(msg_type, tls_server_hello)
  // RFC 8446 §4.1.3: legacy_version is the first two body bytes and stays at TLS 1.2's number.
  assert_eq(qv_hex(body[0:2].to_owned()), "0303")
  guard decode_server_hello(body[:]) is Some(decoded) else {
    fail("the ServerHello should decode")
  }
  assert_eq(tls_server_hello_version(decoded), Some(tls_version_13))
  guard tls_find_extension(decoded.extensions, tls_ext_supported_versions)
    is Some(selected) else {
    fail("the ServerHello should carry supported_versions")
  }
  assert_eq(qv_hex(selected.data), "0304")
  assert_eq(tls_server_hello_key_share(decoded) is Some(_), true)
}

///|
test "hello extensions: RFC 8448 §3's ServerHello puts 0x0304 in the extension and 0x0303 in the field" {
  guard tls_parse_handshake(qv_hexb(rfc8448_server_hello)[:]) is Some((_, body)) else {
    fail("the RFC 8448 ServerHello should frame")
  }
  assert_eq(qv_hex(body[0:2].to_owned()), "0303")
  guard decode_server_hello(body[:]) is Some(sh) else {
    fail("the RFC 8448 ServerHello should decode")
  }
  guard tls_find_extension(sh.extensions, tls_ext_supported_versions)
    is Some(selected) else {
    fail("the RFC 8448 ServerHello should carry supported_versions")
  }
  assert_eq(qv_hex(selected.data), "0304")
  assert_eq(tls_server_hello_version(sh), Some(tls_version_13))
  assert_eq(tls13_is_hello_retry_request(sh), false)
}

///|
test "hello extensions: RFC 8448 §3's ClientHello negotiates x25519 and ES256 off its own bytes" {
  assert_eq(
    tls13_negotiate_client_hello(qv_hexb(rfc8448_client_hello)),
    Negotiated(
      group=tls_group_x25519,
      client_key=qv_hexb(
        "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c",
      ),
      scheme=tls_sig_ecdsa_secp256r1_sha256,
    ),
  )
}

///|
test "hello extensions: a group this build cannot run is a handshake_failure" {
  let ch = hello_offering([
    tls_supported_versions_extension([tls_version_13]),
    tls_supported_groups_extension([tls_group_secp384r1]),
    tls_signature_algorithms_extension([tls_sig_ecdsa_secp256r1_sha256]),
    client_key_share([(tls_group_secp384r1, Bytes::make(97, b'\x04'))]),
  ])
  assert_eq(negotiation_alert(ch), Some(tls_fatal(tls_alert_handshake_failure)))
}

///|
test "hello extensions: a signature scheme this build cannot sign is a handshake_failure" {
  let ch = hello_offering([
    tls_supported_versions_extension([tls_version_13]),
    tls_supported_groups_extension([tls_group_x25519]),
    tls_signature_algorithms_extension([tls_sig_rsa_pss_rsae_sha256]),
    client_key_share([(tls_group_x25519, a_client_share())]),
  ])
  assert_eq(negotiation_alert(ch), Some(tls_fatal(tls_alert_handshake_failure)))
}

///|
test "hello extensions: a ClientHello missing any mandatory extension is a missing_extension" {
  // RFC 8446 §9.2 requires all four of these on a 1.3 ClientHello.
  let versions = tls_supported_versions_extension([tls_version_13])
  let groups = tls_supported_groups_extension([tls_group_x25519])
  let schemes = tls_signature_algorithms_extension([
    tls_sig_ecdsa_secp256r1_sha256,
  ])
  let shares = client_key_share([(tls_group_x25519, a_client_share())])
  let missing = Some(tls_fatal(tls_alert_missing_extension))
  assert_eq(
    negotiation_alert(hello_offering([groups, schemes, shares])),
    missing,
  )
  assert_eq(
    negotiation_alert(hello_offering([versions, schemes, shares])),
    missing,
  )
  assert_eq(
    negotiation_alert(hello_offering([versions, groups, shares])),
    missing,
  )
  assert_eq(
    negotiation_alert(hello_offering([versions, groups, schemes])),
    missing,
  )
}

///|
test "hello extensions: a client that does not offer 1.3 is a protocol_version" {
  let ch = hello_offering([
    tls_supported_versions_extension([tls_legacy_version]),
    tls_supported_groups_extension([tls_group_x25519]),
    tls_signature_algorithms_extension([tls_sig_ecdsa_secp256r1_sha256]),
    client_key_share([(tls_group_x25519, a_client_share())]),
  ])
  assert_eq(negotiation_alert(ch), Some(tls_fatal(tls_alert_protocol_version)))
}

///|
test "hello extensions: a key share that contradicts the ClientHello is an illegal_parameter" {
  // §4.2.8 — a share for a group the client never listed in supported_groups.
  let unlisted = hello_offering([
    tls_supported_versions_extension([tls_version_13]),
    tls_supported_groups_extension([tls_group_x25519]),
    tls_signature_algorithms_extension([tls_sig_ecdsa_secp256r1_sha256]),
    client_key_share([
      (tls_group_x25519, a_client_share()),
      (tls_group_secp384r1, Bytes::make(97, b'\x04')),
    ]),
  ])
  assert_eq(
    negotiation_alert(unlisted),
    Some(tls_fatal(tls_alert_illegal_parameter)),
  )
  // An x25519 share that is not a 32-byte Montgomery-u coordinate (RFC 7748 §5).
  let wrong_length = hello_offering([
    tls_supported_versions_extension([tls_version_13]),
    tls_supported_groups_extension([tls_group_x25519]),
    tls_signature_algorithms_extension([tls_sig_ecdsa_secp256r1_sha256]),
    client_key_share([(tls_group_x25519, Bytes::make(31, b'\x23'))]),
  ])
  assert_eq(
    negotiation_alert(wrong_length),
    Some(tls_fatal(tls_alert_illegal_parameter)),
  )
}

///|
test "hello extensions: a message that is not a well-formed ClientHello is a decode_error" {
  let truncated = try {
    let _ = tls13_negotiate_client_hello(b"\x01\x00\x00\x10")
    None
  } catch {
    a => Some(a)
  }
  assert_eq(truncated, Some(tls_fatal(tls_alert_decode_error)))
  // A ServerHello fed to the server side is the wrong message, not a malformed one.
  let wrong_type = try {
    let _ = tls13_negotiate_client_hello(qv_hexb(rfc8448_server_hello))
    None
  } catch {
    a => Some(a)
  }
  assert_eq(wrong_type, Some(tls_fatal(tls_alert_unexpected_message)))
}
