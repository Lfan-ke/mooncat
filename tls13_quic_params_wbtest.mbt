// Carrying a QUIC transport-parameter block through a TLS handshake extension (RFC 9001 §8.2).

///|
test "quic transport params: an endpoint's block round-trips through its TLS extension" {
  let params = [
    transport_param_int(tp_initial_max_data, 66666),
    transport_param_int(tp_initial_max_streams_bidi, 233),
    transport_param_int(tp_max_idle_timeout, 23333),
    transport_param_int(tp_active_connection_id_limit, 8),
  ]
  let ext = tls_quic_transport_params_extension(params)
  // The extension is 0x0039 and its data is exactly the transport-parameter block.
  assert_eq(ext.ext_type, 0x0039)
  assert_eq(ext.data, encode_transport_params(params))
  // Read back from a ClientHello's extension list, in order.
  let client_exts : Array[TlsExtension] = [ext]
  assert_eq(tls_hello_quic_transport_params(client_exts), params)
  // And their integer values decode as sent.
  let got = tls_hello_quic_transport_params(client_exts)
  assert_eq(transport_param_as_int(got[0]), Some(66666UL))
  assert_eq(transport_param_as_int(got[1]), Some(233UL))
  // No extension: no parameters.
  assert_eq(tls_hello_quic_transport_params([]), [])
}
