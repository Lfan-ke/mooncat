// A self-signed X.509 v3 P-256 certificate (RFC 5280). The DER this produces was validated with
// OpenSSL 3.2.4: `openssl x509 -inform DER` parses it (subject/issuer CN, ecdsa-with-SHA256,
// id-ecPublicKey prime256v1) and `openssl verify` returns OK — the self-signature checks out.

///|
test "x509: a self-signed P-256 certificate carries a valid ES256 signature over its TBS" {
  let key = EcdsaPrivateKey::from_hex(
    "233333333333333333333333333333333333333333333333333333333333eeff",
  )
  let cert = x509_self_signed(
    key, b"\x0d\x23\x33", "lfanke.example", "250101000000Z", "350101000000Z",
  )
  // Byte-exact against the DER that OpenSSL validated (deterministic RFC 6979 signing): any
  // change to the ASN.1 assembly or the signature moves these bytes.
  assert_eq(
    cert,
    qv_hexb(
      "308201203081c7a00302010202030d2333300a06082a8648ce3d04030230193117301506035504030c0e6c66616e6b652e6578616d706c65301e170d3235303130313030303030305a170d3335303130313030303030305a30193117301506035504030c0e6c66616e6b652e6578616d706c653059301306072a8648ce3d020106082a8648ce3d03010703420004a115f872600665c589ff3f4687e29794b9af522dcf6920265fb76db77a5a093a7499dd913c1f2e028600cd29f3f1e34bab9db77349d7ffba7c99e732a1d96f0f300a06082a8648ce3d0403020348003045022100f68eb723ff01316c1dcdfda7fe869c92b27c2a0484f467a734cca98723b8146402205b5d439b9180abde78c096dc46932dad312abac9e2d79acca457e7830668b2e0",
    ),
  )
  // The signature is valid over the TBSCertificate: rebuild the TBS (deterministic RFC 6979
  // signing) and verify with the certificate's own public key — a self-signature.
  let tbs = x509_tbs_certificate(
    b"\x0d\x23\x33",
    "lfanke.example",
    "250101000000Z",
    "350101000000Z",
    key.public_key(),
  )
  let raw = ecdsa_p256_sha256_sign(tbs, key)
  assert_eq(ecdsa_p256_sha256_verify(tbs, raw, key.public_key()), true)
  // The DER certificate rides the TLS 1.3 Certificate message and comes back out intact.
  let msg = tls13_encode_certificate(b"", [cert])
  assert_eq(tls13_decode_certificate(msg[:]), Some((b"", [cert])))
}
