///|
test "QUIC packet number encodes per RFC 9000 A.2" {
  // full = 0xac5c02, largest acked = 0xabe8bc -> two bytes, 0x5c02.
  assert_eq(quic_pn_len(0xac5c02L, Some(0xabe8bcL)), 2)
  assert_eq(qv_hex(quic_pn_encode(0xac5c02L, Some(0xabe8bcL))), "5c02")
}

///|
test "QUIC packet number decodes per RFC 9000 A.3" {
  // largest received = 0xa82f30ea, truncated = 0x9b32 (16 bits) -> 0xa82f9b32.
  assert_eq(quic_pn_decode(0xa82f30eaL, 0x9b32L, 16), 0xa82f9b32L)
}

///|
test "QUIC packet number encode/decode round-trips" {
  let cases = [
    (0xac5c02L, 0xabe8bcL),
    (0xa82f9b32L, 0xa82f30eaL),
    (100L, 50L),
    (0xffffL, 0x8000L),
    (0x3fffffffL, 0x3ffffff0L),
  ]
  for c in cases {
    let (full, lacked) = c
    let nb = quic_pn_len(full, Some(lacked))
    let enc = quic_pn_encode(full, Some(lacked))
    assert_eq(enc.length(), nb)
    let mut tr = 0L
    for i = 0; i < enc.length(); i = i + 1 {
      tr = (tr << 8) | enc[i].to_int().to_int64()
    }
    assert_eq(quic_pn_decode(lacked, tr, nb * 8), full)
  }
}
