///|
test "SHA-256 matches the NIST vectors" {
  assert_eq(
    qv_hex(sha256(b"")),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert_eq(
    qv_hex(sha256(b"abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "SHA-256 handles a multi-block message across the pad boundary" {
  // 200 'a's crosses the 64-byte block and the 56-byte pad threshold; the digest
  // is from a reference SHA-256.
  let buf = Buffer()
  for _i = 0; _i < 200; _i = _i + 1 {
    buf.write_byte(b'a')
  }
  assert_eq(
    qv_hex(sha256(buf.to_bytes())),
    "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5",
  )
}
