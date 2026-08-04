///|
/// A self-signed X.509 v3 P-256 certificate (RFC 5280) — the identity a TLS 1.3
/// server presents. It is built from the ASN.1 DER primitives, signed with
/// ES256, its self-signature is verified against its own key, and it rides a TLS
/// Certificate message and comes back out intact.
///
///     moon run examples/10-x509 --target native
#coverage.skip
fn main {
  let key = @mooncat.EcdsaPrivateKey::from_hex(
    "233333333333333333333333333333333333333333333333333333333333eeff",
  )
  let cert = @mooncat.x509_self_signed(
    key, b"\x0d\x23\x33", "lfanke.example", "250101000000Z", "350101000000Z",
  )
  println("certificate DER  = \{cert.length()} bytes")
  println("prefix           = \{hex(cert[0:12].to_owned())}...")
  let tbs = @mooncat.x509_tbs_certificate(
    b"\x0d\x23\x33",
    "lfanke.example",
    "250101000000Z",
    "350101000000Z",
    key.public_key(),
  )
  let raw = @mooncat.ecdsa_p256_sha256_sign(tbs, key)
  println(
    "self-signature valid = \{@mooncat.ecdsa_p256_sha256_verify(tbs, raw, key.public_key())}",
  )
  let msg = @mooncat.tls13_encode_certificate(b"", [cert])
  let ok = match @mooncat.tls13_decode_certificate(msg[:]) {
    Some((ctx, chain)) =>
      ctx.length() == 0 && chain.length() == 1 && chain[0] == cert
    None => false
  }
  println("round-trips through TLS Certificate = \{ok}")
  println(
    "subject_public_key_info = \{@mooncat.x509_subject_public_key_info(key.public_key()).length()} bytes",
  )
  println("alg ecdsa-with-SHA256   = \{hex(@mooncat.x509_alg_ecdsa_sha256())}")
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
