///|
test "header-protection mask matches RFC 9001 A.2" {
  let hp = qv_hexb("9f50449e04a0e810283a1e9933adedd2")
  let sample = qv_hexb("d1b1c98dd7689fb8ec11d242b123dc9b")
  assert_eq(qv_hex(quic_hp_mask(hp, sample)), "437b9aec36")
}

///|
test "the RFC 9001 A.2 client Initial header protects to the published bytes" {
  let hp = qv_hexb("9f50449e04a0e810283a1e9933adedd2")
  // 22-byte unprotected header (first byte c3, pn 00000002) then the A.2 sample as
  // the first 16 ciphertext bytes; pn field starts at offset 18.
  let packet = qv_hexb(
    "c30000000108" +
    "8394c8f03e515708" +
    "0000449e00000002" +
    "d1b1c98dd7689fb8ec11d242b123dc9b",
  )
  let masked = quic_header_protect(packet, 18, 4, hp)
  // First byte c3 -> c0, packet number 00000002 -> 7b9aec34.
  assert_eq(
    qv_hex(masked[0:22].to_owned()),
    "c00000000108" + "8394c8f03e515708" + "0000449e7b9aec34",
  )
  // Removing protection recovers the original header and the 4-byte pn length.
  let (unprotected, pn_len) = quic_header_unprotect(masked, 18, hp)
  assert_eq(qv_hex(unprotected), qv_hex(packet))
  assert_eq(pn_len, 4)
}

///|
test "header protection round-trips on a short header" {
  let hp = qv_hexb("11223344556677889900aabbccddeeff")
  // Short header: first byte 0x40 (fixed bit set, form bit clear), 2-byte pn 0x1234.
  let packet = qv_hexb(
    "41" + "1234" + "aabbccddeeff00112233445566778899" + "0011",
  )
  let masked = quic_header_protect(packet, 1, 2, hp)
  assert_eq(qv_hex(masked) == qv_hex(packet), false)
  let (unprotected, pn_len) = quic_header_unprotect(masked, 1, hp)
  assert_eq(qv_hex(unprotected), qv_hex(packet))
  assert_eq(pn_len, 2)
}
