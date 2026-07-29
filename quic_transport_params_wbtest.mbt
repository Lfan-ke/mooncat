///|
test "transport parameters encode to the RFC 9000 §18 (id, length, value) form" {
  let params : Array[TransportParam] = [
    transport_param_int(tp_initial_max_data, 1048576UL),
    transport_param_int(tp_initial_max_streams_bidi, 100UL),
    // initial_source_connection_id carries raw bytes, not a varint.
    { id: tp_initial_source_connection_id, value: qv_hexb("8394c8f03e515708") },
  ]
  // id 04 len 04 value 80100000 (varint 1048576); id 08 len 02 value 4064 (100);
  // id 0f len 08 value = the 8-byte connection id.
  assert_eq(
    qv_hex(encode_transport_params(params)),
    "040480100000080240640f088394c8f03e515708",
  )
}

///|
test "transport parameters round-trip and integer values read back" {
  let params : Array[TransportParam] = [
    transport_param_int(tp_max_idle_timeout, 30000UL),
    transport_param_int(tp_active_connection_id_limit, 8UL),
    transport_param_int(tp_max_udp_payload_size, 1472UL),
  ]
  let encoded = encode_transport_params(params)
  match decode_transport_params(encoded[:]) {
    Some(got) => {
      assert_eq(got.length(), 3)
      assert_eq(got[0].id, tp_max_idle_timeout)
      assert_eq(transport_param_as_int(got[0]), Some(30000UL))
      assert_eq(transport_param_as_int(got[2]), Some(1472UL))
    }
    None => fail("transport params should decode")
  }
}

///|
test "a truncated transport-parameter block decodes to None" {
  // id 04, length 04, but only two value bytes supplied.
  assert_eq(decode_transport_params(qv_hexb("04048010")[:]) is None, true)
}
