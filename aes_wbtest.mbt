///|
test "AES-128 encrypts the FIPS-197 Appendix C.1 known-answer block" {
  let key = qv_hexb("000102030405060708090a0b0c0d0e0f")
  let pt = qv_hexb("00112233445566778899aabbccddeeff")
  let sched = aes128_key_schedule(key)
  assert_eq(
    qv_hex(aes128_encrypt_block(sched, pt)),
    "69c4e0d86a7b0430d8cdb78070b4c55a",
  )
}

///|
test "AES-128 encrypts the FIPS-197 Appendix B worked example" {
  // key 2b7e1516..., input 3243f6a8... -> 3925841d02dc09fbdc118597196a0b32.
  let key = qv_hexb("2b7e151628aed2a6abf7158809cf4f3c")
  let pt = qv_hexb("3243f6a8885a308d313198a2e0370734")
  let sched = aes128_key_schedule(key)
  assert_eq(
    qv_hex(aes128_encrypt_block(sched, pt)),
    "3925841d02dc09fbdc118597196a0b32",
  )
}
