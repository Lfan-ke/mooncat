///|
/// The hash primitives the TLS 1.3 / QUIC key schedule is built on: SHA-1
/// (RFC 3174, the WebSocket accept key), SHA-256 (FIPS 180-4), and HMAC-SHA256
/// (RFC 2104 / RFC 4231). Each digest is printed as hex against its published
/// test vector.
///
///     moon run examples/03-hash --target native
#coverage.skip
fn main {
  // SHA-1 (RFC 3174 §7.3).
  println("sha1(\"abc\")   = \{hex(@mooncat.sha1(b"abc"))}")
  // SHA-256 (FIPS 180-4).
  println("sha256(\"\")    = \{hex(@mooncat.sha256(b""))}")
  println("sha256(\"abc\") = \{hex(@mooncat.sha256(b"abc"))}")
  // HMAC-SHA256 (RFC 4231 Test Case 2).
  let mac = @mooncat.hmac_sha256(b"Jefe", b"what do ya want for nothing?")
  println("hmac(Jefe...) = \{hex(mac)}")
  let vec = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  println("matches RFC 4231 TC2 = \{hex(mac) == vec}")
}

///|
/// Lowercase hex of a byte string.
fn hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}
