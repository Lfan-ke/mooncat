// SHA-1 (FIPS 180-4) against the standard test vectors.

///|
test "sha1: the FIPS 180-4 and RFC 3174 test vectors" {
  assert_eq(sha1(b""), qv_hexb("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
  assert_eq(sha1(b"abc"), qv_hexb("a9993e364706816aba3e25717850c26c9cd0d89d"))
  assert_eq(
    sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    qv_hexb("84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
  )
  assert_eq(
    sha1(b"The quick brown fox jumps over the lazy dog"),
    qv_hexb("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
  )
}

///|
test "sha1: a message spanning multiple blocks" {
  // 1000 'a' bytes exercises the multi-block path.
  let m = Bytes::make(1000, b'a')
  assert_eq(sha1(m), qv_hexb("291e9a6c66994949b57ba5e650361e98fc36b1ba"))
}
