///|
/// A `Bytes` of `n` copies of the byte `v`.
fn rep_byte(v : Int, n : Int) -> Bytes {
  let b = Buffer()
  for _i = 0; _i < n; _i = _i + 1 {
    b.write_byte(v.to_byte())
  }
  b.to_bytes()
}

///|
test "HMAC-SHA256 matches the RFC 4231 vectors" {
  // TC1: key 0x0b x20, data "Hi There".
  assert_eq(
    qv_hex(hmac_sha256(rep_byte(0x0b, 20), b"Hi There")),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  // TC2: key "Jefe", data "what do ya want for nothing?".
  assert_eq(
    qv_hex(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
}

///|
test "HMAC-SHA256 handles a key longer than the block size (RFC 4231 TC6)" {
  // Key 0xaa x131 exceeds the 64-byte block, so it is hashed down to 32 bytes first.
  let key = rep_byte(0xaa, 131)
  assert_eq(
    qv_hex(
      hmac_sha256(
        key, b"Test Using Larger Than Block-Size Key - Hash Key First",
      ),
    ),
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
  )
}
