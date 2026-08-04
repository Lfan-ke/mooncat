///|
/// ECDSA over NIST P-256 with SHA-256 (ES256) — the TLS 1.3 CertificateVerify
/// signature (RFC 8446 §4.4.3). A private scalar signs a message to a raw
/// `r || s`; the public key verifies it, a tampered message is refused, and the
/// RFC 6979 deterministic nonce makes signing reproducible.
///
///     moon run examples/08-ecdsa --target native
#coverage.skip
fn main {
  let key = @mooncat.EcdsaPrivateKey::from_hex(
    "2333333333333333333333333333333333333333333333333333333333333333",
  )
  let pubk = key.public_key()
  let msg = b"the quick brown fox, heke1228"
  let sig = @mooncat.ecdsa_p256_sha256_sign(msg, key)
  println("signature r||s = \{hex(sig)}")
  println("length         = \{sig.length()} bytes")
  println(
    "verify (msg)      = \{@mooncat.ecdsa_p256_sha256_verify(msg, sig, pubk)}",
  )
  println(
    "verify (tampered) = \{@mooncat.ecdsa_p256_sha256_verify(b"different heke1228", sig, pubk)}",
  )
  let again = @mooncat.ecdsa_p256_sha256_sign(msg, key)
  println("deterministic (RFC 6979) = \{sig == again}")
}

///|
fn hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}
