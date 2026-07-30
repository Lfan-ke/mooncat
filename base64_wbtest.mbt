// Base64 (RFC 4648 §10 test vectors).

///|
test "base64: the RFC 4648 §10 encode vectors" {
  assert_eq(base64_encode(b""), b"")
  assert_eq(base64_encode(b"f"), b"Zg==")
  assert_eq(base64_encode(b"fo"), b"Zm8=")
  assert_eq(base64_encode(b"foo"), b"Zm9v")
  assert_eq(base64_encode(b"foob"), b"Zm9vYg==")
  assert_eq(base64_encode(b"fooba"), b"Zm9vYmE=")
  assert_eq(base64_encode(b"foobar"), b"Zm9vYmFy")
}

///|
test "base64: decode is the inverse of encode across every remainder" {
  assert_eq(base64_decode(b"Zg=="), b"f")
  assert_eq(base64_decode(b"Zm8="), b"fo")
  assert_eq(base64_decode(b"Zm9vYmFy"), b"foobar")
  for n = 0; n < 12; n = n + 1 {
    let m = Bytes::make(n, b'\x2a')
    assert_eq(base64_decode(base64_encode(m)), m)
  }
}
