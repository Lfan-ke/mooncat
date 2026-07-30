// A minimal X.509 v3 certificate (RFC 5280) for a P-256 / ECDSA-with-SHA256 server, built on
// the ASN.1 DER primitives. A TLS 1.3 server sends this in its Certificate message so a client
// can bind the handshake to a public key; mooncat signs it with the same ES256 primitive the
// CertificateVerify uses. This produces a real, self-signed DER certificate — the identity curl
// parses — replacing the opaque placeholder the handshake carried.

///|
/// The ecdsa-with-SHA256 AlgorithmIdentifier (RFC 5758): a SEQUENCE of just the OID, ECDSA
/// taking no parameters.
pub fn x509_alg_ecdsa_sha256() -> Bytes {
  der_sequence([der_oid([1, 2, 840, 10045, 4, 3, 2])])
}

///|
/// The id-ecPublicKey with the prime256v1 (P-256) curve AlgorithmIdentifier (RFC 5480).
pub fn x509_alg_ec_public_key() -> Bytes {
  der_sequence([
    der_oid([1, 2, 840, 10045, 2, 1]),
    der_oid([1, 2, 840, 10045, 3, 1, 7]),
  ])
}

///|
/// A Name with a single commonName attribute: RDNSequence → RelativeDistinguishedName (SET) →
/// AttributeTypeAndValue (SEQUENCE of the commonName OID 2.5.4.3 and the UTF8String value).
pub fn x509_common_name(cn : String) -> Bytes {
  der_sequence([
    der_set([der_sequence([der_oid([2, 5, 4, 3]), der_utf8_string(cn)])]),
  ])
}

///|
/// A Validity: notBefore and notAfter as UTCTime `YYMMDDHHMMSSZ`.
pub fn x509_validity(not_before : String, not_after : String) -> Bytes {
  der_sequence([der_utc_time(not_before), der_utc_time(not_after)])
}

///|
/// The uncompressed SEC1 encoding of an EC public key: `0x04 || X || Y`, each coordinate 32
/// big-endian bytes for P-256.
fn x509_ec_point(pub_key : EcdsaPublicKey) -> Bytes {
  let buf = Buffer()
  buf.write_byte(b'\x04')
  buf.write_bytes(pub_key.x.to_octets(length=32)[:])
  buf.write_bytes(pub_key.y.to_octets(length=32)[:])
  buf.to_bytes()
}

///|
/// A SubjectPublicKeyInfo for a P-256 key: the ecPublicKey/prime256v1 algorithm and the
/// uncompressed point as a BIT STRING.
pub fn x509_subject_public_key_info(pub_key : EcdsaPublicKey) -> Bytes {
  der_sequence([
    x509_alg_ec_public_key(),
    der_bit_string(x509_ec_point(pub_key)),
  ])
}

///|
/// The TBSCertificate (RFC 5280 §4.1.2): version v3 `[0] EXPLICIT INTEGER 2`, the serial number,
/// the signature algorithm, the issuer, the validity, the subject, and the SubjectPublicKeyInfo.
/// Self-signed, so issuer and subject are the same commonName. Extensions are omitted (a valid,
/// minimal profile).
pub fn x509_tbs_certificate(
  serial : Bytes,
  common_name : String,
  not_before : String,
  not_after : String,
  pub_key : EcdsaPublicKey,
) -> Bytes {
  der_sequence([
    der_explicit(0, der_integer(b"\x02")),
    der_integer(serial),
    x509_alg_ecdsa_sha256(),
    x509_common_name(common_name),
    x509_validity(not_before, not_after),
    x509_common_name(common_name),
    x509_subject_public_key_info(pub_key),
  ])
}

///|
/// A self-signed X.509 certificate: build the TBSCertificate for `key`'s public key, sign its
/// DER with ES256, DER-encode the `r`/`s` signature (RFC 5280 requires the ECDSA-Sig-Value
/// SEQUENCE, not the raw concatenation), and wrap TBS + algorithm + signature in the outer
/// Certificate SEQUENCE.
pub fn x509_self_signed(
  key : EcdsaPrivateKey,
  serial : Bytes,
  common_name : String,
  not_before : String,
  not_after : String,
) -> Bytes {
  let pub_key = key.public_key()
  let tbs = x509_tbs_certificate(
    serial, common_name, not_before, not_after, pub_key,
  )
  let raw = ecdsa_p256_sha256_sign(tbs, key)
  let sig = der_sequence([
    der_integer(raw[0:32].to_owned()),
    der_integer(raw[32:64].to_owned()),
  ])
  der_sequence([tbs, x509_alg_ecdsa_sha256(), der_bit_string(sig)])
}
