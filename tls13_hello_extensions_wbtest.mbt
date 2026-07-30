// Threading ALPN and the QUIC transport parameters into the real handshake messages: a
// ClientHello offering key_share + ALPN + transport parameters, and a server EncryptedExtensions
// naming the ALPN it picked and carrying its transport parameters (RFC 8446 §4.3.1, RFC 9001 §8.2).

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
