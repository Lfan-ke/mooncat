// QUIC key schedule against RFC 9001: the Initial key/iv/hp derivation vectors from
// Appendix A.1, and the key-update secret advance from §6.1.

///|
test "RFC 9001 A.1: Initial keys derive to the published key/iv/hp" {
  let dcid = qv_hexb("8394c8f03e515708")
  let client = quic_packet_keys(quic_client_initial_secret(dcid))
  assert_eq(qv_hex(client.key), "1f369613dd76d5467730efcbe3b1a22d")
  assert_eq(qv_hex(client.iv), "fa044b2f42a3fd3b46fb255c")
  assert_eq(qv_hex(client.hp), "9f50449e04a0e810283a1e9933adedd2")
  let server = quic_packet_keys(quic_server_initial_secret(dcid))
  assert_eq(qv_hex(server.key), "cf3a5331653c364c88f0f379b6067e37")
  assert_eq(qv_hex(server.iv), "0ac1493ca1905853b0bba03e")
  assert_eq(qv_hex(server.hp), "c206b8d9b9f0f37644430b490eeaa314")
}

///|
test "RFC 9001 §6.1: key update advances the secret and re-keys" {
  let dcid = qv_hexb("8394c8f03e515708")
  let secret = quic_client_initial_secret(dcid)
  let updated = quic_key_update(secret)
  // The updated secret differs from the current one.
  assert_eq(qv_hex(updated) == qv_hex(secret), false)
  // The derivation is deterministic.
  assert_eq(qv_hex(quic_key_update(secret)), qv_hex(updated))
  // quic_next_keys yields that secret and the AEAD material derived from it.
  let (next_secret, keys) = quic_next_keys(secret)
  assert_eq(qv_hex(next_secret), qv_hex(updated))
  assert_eq(keys.key.length(), 16)
  assert_eq(keys.iv.length(), 12)
  assert_eq(keys.hp.length(), 16)
  // A second update advances again, distinct from the first.
  assert_eq(qv_hex(quic_key_update(updated)) == qv_hex(updated), false)
}
