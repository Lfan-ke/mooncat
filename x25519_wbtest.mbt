///|
test "X25519 matches the RFC 7748 §5.2 test vector" {
  let k = qv_hexb(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
  )
  let u = qv_hexb(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
  )
  assert_eq(
    qv_hex(x25519(k, u)),
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
  )
}

///|
test "X25519 Diffie-Hellman agrees, per RFC 7748 §6.1" {
  let a_priv = qv_hexb(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let b_priv = qv_hexb(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  // Public keys are the base point scaled by each private key.
  let a_pub = x25519(a_priv, x25519_base())
  assert_eq(
    qv_hex(a_pub),
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  let b_pub = x25519(b_priv, x25519_base())
  // Both sides derive the same shared secret.
  let shared_a = x25519(a_priv, b_pub)
  let shared_b = x25519(b_priv, a_pub)
  assert_eq(qv_hex(shared_a), qv_hex(shared_b))
  assert_eq(
    qv_hex(shared_a),
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
}
